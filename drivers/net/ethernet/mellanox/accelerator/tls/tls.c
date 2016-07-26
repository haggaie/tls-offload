/*
 * Copyright (c) 2015-2016 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "tls.h"
#include "tls_sysfs.h"
#include "tls_hw.h"
#include <linux/netdevice.h>

#include "../../../../crypto/af_ktls.h"

static LIST_HEAD(mlx_tls_devs);
static DEFINE_MUTEX(mlx_tls_mutex);

/* Start of context identifiers range (inclusive) */
#define SWID_START 5
/* End of context identifiers range (exclusive) */
#define SWID_END (1<<24)

/* must hold mlx_tls_mutex to call this function */
static struct mlx_tls_dev *find_mlx_tls_dev_by_netdev(
		struct net_device *netdev)
{
	struct mlx_tls_dev *dev;

	list_for_each_entry(dev, &mlx_tls_devs, accel_dev_list) {
		if (dev->netdev == netdev)
			return dev;
	}

	return NULL;
}

static int mlx_ktls_add(struct net_device *netdev, struct sock *sk,
		struct ktls_keys *keys) {
	struct tls_offload_context *context;
	struct mlx_tls_dev *dev;
	int swid;
	int ret;

	pr_info("mlx_ktls_add called\n");
	dev = mlx_tls_find_dev_by_netdev(netdev);
	if (!dev) {
		pr_err("mlx_ktls_add(): tls dev not found\n");
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&dev->id_mutex);
	swid = idr_alloc_cyclic(&dev->swid_idr, NULL, SWID_START, SWID_END,
			GFP_ATOMIC);
	mutex_unlock(&dev->id_mutex);
	if (swid < 0) {
		pr_err("mlx_ktls_add(): Failed to allocate swid\n");
		ret = swid;
		goto out;
	}

	context = kmalloc(sizeof(struct tls_offload_context), GFP_KERNEL);
	if (!context) {
		mutex_lock(&dev->id_mutex);
		idr_remove(&dev->swid_idr, context->swid);
		mutex_unlock(&dev->id_mutex);
		ret = -ENOMEM;
		goto out;
	}

	context->swid = swid;
	context->expectedSN = tcp_sk(sk)->write_seq;
	spin_lock_init(&context->lock);
	sk->sk_tls_offload = context;

	mlx_ktls_hw_start_cmd(dev, sk, context, keys);
	try_module_get(THIS_MODULE);
	ret = 0;
out:
	return ret;
}


static void mlx_ktls_del(struct net_device *netdev, struct sock *sk)
{
	struct tls_offload_context *context = sk->sk_tls_offload;

	if (context)
		mlx_ktls_hw_stop_cmd(netdev, sk);
	else
		pr_err("delete non-offloaded context\n");
}

static const struct ktls_ops mlx_ktls_ops = {
	.ktls_dev_add = mlx_ktls_add,
	.ktls_dev_del = mlx_ktls_del
};

struct mlx_tls_dev *mlx_tls_find_dev_by_netdev(struct net_device *netdev)
{
	struct mlx_tls_dev *dev;

	mutex_lock(&mlx_tls_mutex);
	dev = find_mlx_tls_dev_by_netdev(netdev);
	mutex_unlock(&mlx_tls_mutex);
	return dev;
}

static void remove_pet(struct sk_buff *skb, struct pet *pet)
{
	struct ethhdr *old_eth;
	struct ethhdr *new_eth;

	pr_debug("remove_pet started\n");

	memcpy(pet, skb->data, sizeof(*pet));
	old_eth = (struct ethhdr *)(skb->data - sizeof(struct ethhdr));
	new_eth = (struct ethhdr *)(skb_pull_inline(skb, sizeof(struct pet)) -
		sizeof(struct ethhdr));
	skb->mac_header += sizeof(struct pet);

	memmove(new_eth, old_eth, 2 * ETH_ALEN);
	/* Ethertype is already in its new place */
}

#define SYNDROME_OFFLOAD_REQUIRED 32
#define SYNDROME_SYNC 33

static int insert_pet(struct sk_buff *skb)
{
	struct ethhdr *eth;
	struct pet *pet;
	struct tls_offload_context *context;

	pr_debug("insert_pet started\n");
	if (skb_cow_head(skb, sizeof(struct pet)))
		return -ENOMEM;

	eth = (struct ethhdr *)skb_push(skb, sizeof(struct pet));
	skb->mac_header -= sizeof(struct pet);
	pet = (struct pet *)(eth+1);

	memmove(skb->data, skb->data + sizeof(struct pet), 2 * ETH_ALEN);



	eth->h_proto = cpu_to_be16(MLX_TLS_PET_ETHERTYPE);
	pet->syndrome = SYNDROME_OFFLOAD_REQUIRED;

	memset(pet->content.raw, 0, sizeof(pet->content.raw));
	context = (struct tls_offload_context *) skb->sk->sk_tls_offload;
	pet->content.send.sid_high = (context->swid >> 16) & 0xFF;
	pet->content.send.sid_low = htons(context->swid & 0xFFFF);

	if (unlikely(skb->sync_skb)) {
		__be16 tcp_seq_low;

		pet->syndrome = SYNDROME_SYNC;
		tcp_seq_low = htons(ntohl(tcp_hdr(skb)->seq));
		memcpy(pet->content.raw, &tcp_seq_low, sizeof(tcp_seq_low));
	}

	return 0;
}

static struct sk_buff *mlx_tls_tx_handler(struct sk_buff *skb)
{
	struct tls_offload_context *context;
	int datalen;
	unsigned long flags;
	u32 skb_seq;

	pr_debug("mlx_tls_tx_handler started\n");

	if (!skb->sk || !skb->sk->sk_offloaded)
		goto out;

	datalen = skb->len - (skb_transport_offset(skb) + tcp_hdrlen(skb));
	if (!datalen && !skb->sync_skb)
		goto out;

	skb_seq =  ntohl(tcp_hdr(skb)->seq);

	context = (struct tls_offload_context *) skb->sk->sk_tls_offload;
	pr_err("mlx_tls_tx_handler: mapping: %u cpu %u size %u with swid %u expectedSN: %u actualSN: %u\n",
			skb->queue_mapping, smp_processor_id(), skb->len,
			context->swid, context->expectedSN,
			skb_seq);

	insert_pet(skb);
	if (!spin_trylock_irqsave(&context->lock, flags)) {
		pr_info("spin lock for data with swid:%u is busy\n",
				context->swid);
		spin_lock_irqsave(&context->lock, flags);
	}

	context->expectedSN = skb_seq + datalen;
	spin_unlock_irqrestore(&context->lock, flags);
out:
	return skb;
}

static struct sk_buff *mlx_tls_rx_handler(struct sk_buff *skb)
{
	return skb;
}

/* Must hold mlx_tls_mutex to call this function.
 * Assumes that dev->core_ctx is destroyed be the caller
 */
static void mlx_tls_free(struct mlx_tls_dev *dev)
{
	list_del(&dev->accel_dev_list);
	kobject_put(&dev->kobj);
}

void mlx_tls_dev_release(struct kobject *kobj)
{
	struct mlx_tls_dev *tls_dev =
			container_of(kobj, struct mlx_tls_dev, kobj);

	/*
	 * [BP]: TODO - Test the corner case of removing the last reference
	 * while receiving packets that should be handled by the rx_handler.
	 * Do we need some sync here?
	 */

	dev_put(tls_dev->netdev);

	kfree(tls_dev);
}

int mlx_tls_netdev_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct mlx_tls_dev *accel_dev = NULL;

	if (!netdev)
		goto out;

	pr_debug("mlx_tls_netdev_event: %lu\n", event);

	/* We are interested only in net devices going down */
	if (event != NETDEV_UNREGISTER)
		goto out;

	/* Take down all connections using a netdev that is going down */
	mutex_lock(&mlx_tls_mutex);
	accel_dev = find_mlx_tls_dev_by_netdev(netdev);
	if (!accel_dev) {
		pr_debug("mlx_tls_netdev_event: Failed to find tls device for net device\n");
		goto unlock;
	}
	mlx_tls_free(accel_dev);

unlock:
	mutex_unlock(&mlx_tls_mutex);
out:
	return NOTIFY_DONE;
}

/*
 * [BP]: TODO: This function should return an error code and the core should
 * free memory once an error code is returned
 */
void mlx_tls_add_one(struct mlx_accel_core_device *accel_device)
{
	int ret = 0;
	struct mlx_tls_dev *dev = NULL;
	struct net_device *netdev = NULL;
	struct mlx_accel_core_conn_init_attr init_attr = {0};

	pr_debug("mlx_tls_add_one called for %s\n", accel_device->name);

	dev = kzalloc(sizeof(struct mlx_tls_dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&dev->accel_dev_list);
	dev->accel_device = accel_device;
	idr_init(&dev->swid_idr);

	/* [BP]: TODO: Move these constants to a header */
	init_attr.rx_size = 128;
	init_attr.tx_size = 32;
	init_attr.recv_cb = mlx_tls_hw_qp_recv_cb;
	init_attr.cb_arg = dev;
	/* [AY]: TODO: fix port 1 issue */
	dev->conn = mlx_accel_core_conn_create(accel_device, &init_attr);
	if (IS_ERR(dev->conn)) {
		ret = PTR_ERR(dev->conn);
		pr_err("mlx_tls_add_one(): Got error while creating connection %d\n",
				ret);
		goto err_dev;
	}

	netdev = accel_device->ib_dev->get_netdev(accel_device->ib_dev,
			MLX_ACCEL_PORT_NUM);
	if (!netdev) {
		pr_err("mlx_tls_add_one(): Failed to retrieve net device from ib device\n");
		ret = -EINVAL;
		goto err_conn;
	}
	dev->netdev = netdev;

	ret = mlx5e_register_rx_handler(netdev, mlx_tls_rx_handler);
	if (ret) {
		pr_err("mlx_tls_add_one(): Got error while registering RX handler %d\n", ret);
		goto err_netdev;
	}

	ret = mlx5e_register_tx_handler(netdev, mlx_tls_tx_handler);
	if (ret) {
		pr_err("mlx_tls_add_one(): Got error while registering TX handler %d\n", ret);
		goto err_rx_register;
	}

	ret = tls_sysfs_init_and_add(&dev->kobj,
			mlx_accel_core_kobj(dev->accel_device),
			"%s",
			"accel_dev");
	if (ret) {
		pr_err("mlx_tls_add_one(): Got error from kobject_init_and_add %d\n", ret);
		goto err_tx_register;
	}

	mutex_init(&dev->id_mutex);
	mutex_lock(&mlx_tls_mutex);
	list_add(&dev->accel_dev_list, &mlx_tls_devs);
	mutex_unlock(&mlx_tls_mutex);

	dev->netdev->ktls_ops = &mlx_ktls_ops;
	goto out;

err_tx_register:
	mlx5e_unregister_tx_handler(netdev);
err_rx_register:
	mlx5e_unregister_rx_handler(netdev);
err_netdev:
	dev_put(netdev);
err_conn:
	mlx_accel_core_conn_destroy(dev->conn);
err_dev:
	kfree(dev);
out:
	return;
}

/* [BP]: TODO - Remove all SA entries on mlx_xfrm_del_state */
/* [BP]: TODO - How do we make sure that all packets inflight are dropped? */
void mlx_tls_remove_one(struct mlx_accel_core_device *accel_device)
{
	struct mlx_tls_dev *dev;

	pr_debug("mlx_tls_remove_one called for %s\n", accel_device->name);

	mutex_lock(&mlx_tls_mutex);

	list_for_each_entry(dev, &mlx_tls_devs, accel_dev_list) {
		if (dev->accel_device == accel_device) {
			dev->netdev->ktls_ops = NULL;
			mlx5e_unregister_rx_handler(dev->netdev);
			mlx5e_unregister_tx_handler(dev->netdev);
			mlx_accel_core_conn_destroy(dev->conn);
			mlx_tls_free(dev);
			break;
		}
	}
	mutex_unlock(&mlx_tls_mutex);
}
