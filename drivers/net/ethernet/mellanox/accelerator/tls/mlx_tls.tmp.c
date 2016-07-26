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

#include <linux/list.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/module.h>

#include "../core/accel_core_sdk.h"
#include "mlx_tls_cmds.h"
#include "mlx_tls.h"

#define DRIVER_NAME "mlx_accelerator"
#define DRIVER_VERSION "0.1"
#define DRIVER_RELDATE  "January 2016"

/* [BP]: TODO - change these details */
MODULE_AUTHOR("Jhon Snow <Jhon@WinterIsComing.com>");
MODULE_DESCRIPTION("Mellanox FPGA Accelerator Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRIVER_VERSION);


/* Structure definitions begin */
struct handler_context {
	struct kref ref;
	struct list_head list;
	struct net *net;
	int bound_dev_if;
};


struct tx_desc {
	struct list_head list;
	int buf_id;
	u32 seqno;
};

struct mlx_tls_sock_funcs {
	void (*sk_destruct)(struct sock *);
	void (*data_ready)(struct sock *);
	void (*state_change)(struct sock *);
	void (*write_space)(struct sock *);
};
struct mlx_tls_driver {
	struct device *dev;
	struct class *mlx_tls_class;
	dev_t devno;
	struct list_head mlx_tls_devs;
	/* [BP]: TODO: Consider replacing this with a MLX_ACCEL protcol as in
	 * socket(MLX_ACCEL, STREAM)
	 */
	/* replace an attached socket with these ops instead of inet_stream_ops
	 */
	struct proto_ops mlx_tls_stream_ops;
};

struct mlx_tls_fpga_data {
	unsigned int buf_id;
};

struct mlx_tls_dev {
	struct kobject kobj;
	/* List of handler_context */
	struct list_head rx_handlers;
	struct list_head tx_handlers;
	spinlock_t accel_tcp_conns_lock;
	/* List of accelerated tcp connections */
	struct list_head accel_tcp_conns;
	/*TODO: rx_bytes is still unused. It should hold the correct value and be
	 * exposed in sysfs */
	atomic_t rx_bytes;
	struct list_head accel_dev_list;
	u32 dqpn;
	struct mlx_accel_core_ctx *core_ctx;
};

struct mlx_tls_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx_tls_dev *dev, char *buf);
	ssize_t (*store)(struct mlx_tls_dev *dev, const char *buf,
			size_t count);
};

#define MLX_ACCEL_ATTR(_name, _mode, _show, _store) \
	struct mlx_tls_attribute mlx_tls_attr_##_name = { \
			.attr = {.name = __stringify(_name), .mode = _mode}, \
			.show = _show, \
			.store = _store, \
	}
#define to_mlx_tls_dev(obj)  container_of(kobj, struct mlx_tls_dev, kobj)
#define to_mlx_tls_attr(_attr) container_of(attr,\
		struct mlx_tls_attribute, attr)

/* Function declarations */

int mlx5e_register_tx_handler(struct net_device *dev,
		struct sk_buff* (*tx_handler)(struct sk_buff *skb));
int mlx5e_unregister_tx_handler(struct net_device *dev);
#define mlx_register_tx_handler mlx5e_register_tx_handler
#define mlx_unregister_tx_handler mlx5e_unregister_tx_handler

static void mlx_tls_add_one(struct mlx_accel_core_ctx *ctx);
static void mlx_tls_remove_one(struct mlx_accel_core_ctx *ctx);

static void mlx_tls_dev_release(struct kobject *kobj);
static struct mlx_tls_dev *find_mlx_tls_dev_by_netdev(struct net_device
		*netdev);

static int  alloc_mlx_tls_dev(struct mlx_tls_dev **dev,
		struct mlx_accel_core_ctx *ctx);
static ssize_t mlx_tls_attr_show(struct kobject *kobj,
		struct attribute *attr, char *buf);
static ssize_t mlx_tls_attr_store(struct kobject *kobj,
		struct attribute *attr, const char *buf, size_t count);

static ssize_t mlx_tls_sqpn_read(struct mlx_tls_dev *dev, char *buf);
static ssize_t mlx_tls_dqpn_read(struct mlx_tls_dev *dev, char *buf);
static ssize_t mlx_tls_dqpn_write(struct mlx_tls_dev *dev, const char *buf,
		size_t count);
static ssize_t mlx_tls_sgid_read(struct mlx_tls_dev *dev, char *buf);
static ssize_t mlx_tls_dgid_read(struct mlx_tls_dev *dev, char *buf);
static ssize_t mlx_tls_dgid_write(struct mlx_tls_dev *dev, const char *buf,
		size_t count);


/* Globals begin here */
/* [SR] TODO: This can be merged with the struct type definition. */
static struct mlx_tls_driver driver;

static DEFINE_MUTEX(mlx_tls_mutex);

/* [SR] TODO: const? */
static struct mlx_accel_core_client mlx_tls_client = {
	.name   = "mlx_accel",
	.add    = mlx_tls_add_one,
	.remove = mlx_tls_remove_one,
};

/* All these sysfs code should be replaced with an I2C configuration system */
/* [SR] TODO: Migrate this code into core, make it something that can
 * work with simulator in parallel to production FPGA.
 */
static const struct sysfs_ops mlx_tls_dev_sysfs_ops = {
	.show  = mlx_tls_attr_show,
	.store = mlx_tls_attr_store,
};

static MLX_ACCEL_ATTR(sgid, 0444, mlx_tls_sgid_read, NULL);
static MLX_ACCEL_ATTR(dgid, 0666, mlx_tls_dgid_read, mlx_tls_dgid_write);
static MLX_ACCEL_ATTR(sqpn, 0444, mlx_tls_sqpn_read, NULL);
static MLX_ACCEL_ATTR(dqpn, 0666, mlx_tls_dqpn_read, mlx_tls_dqpn_write);

static struct attribute *def_attrs[] = {
	&mlx_tls_attr_sgid.attr,
	&mlx_tls_attr_dgid.attr,
	&mlx_tls_attr_sqpn.attr,
	&mlx_tls_attr_dqpn.attr,
	NULL,
};

static struct kobj_type mlx_tls_dev_type = {
	.release        = mlx_tls_dev_release,
	.sysfs_ops      = &mlx_tls_dev_sysfs_ops,
	.default_attrs  = def_attrs,
};



/*
 * Generic read/write functions that call the specific functions of
 * the attributes...
 */
/* [SR] TODO: Maybe switch to debugfs for easier exposure of attributes? */
static ssize_t mlx_tls_attr_show(struct kobject *kobj, struct attribute *attr,
			char *buf)
{
	struct mlx_tls_dev *dev = to_mlx_tls_dev(kobj);
	struct mlx_tls_attribute *mlx_tls_attr = to_mlx_tls_attr(attr);
	ssize_t ret = -EIO;

	if (mlx_tls_attr->show)
		ret = mlx_tls_attr->show(dev, buf);

	return ret;
}

static ssize_t mlx_tls_attr_store(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	struct mlx_tls_dev *dev = to_mlx_tls_dev(kobj);
	struct mlx_tls_attribute *mlx_tls_attr = to_mlx_tls_attr(attr);
	ssize_t ret = -EIO;

	if (mlx_tls_attr->store)
		ret = mlx_tls_attr->store(dev, buf, count);

	return ret;
}

static ssize_t mlx_tls_dqpn_read(struct mlx_tls_dev *dev, char *buf)
{
	return sprintf(buf, "%d\n", dev->dqpn);
}

static ssize_t mlx_tls_sqpn_read(struct mlx_tls_dev *dev, char *buf)
{
	return sprintf(buf, "%d\n", dev->core_ctx->qp->qp_num);
}


static ssize_t mlx_tls_dqpn_write(struct mlx_tls_dev *dev, const char *buf,
		size_t count)
{
	sscanf(buf, "%u\n", &dev->dqpn);
	/* [SR] TODO: We are planning on keeping this interface in
	 * final version as well? If so, how will we know what DQPN to
	 * use? I guess we should have "allocate-user-QP-slot" API in
	 * the core.
	 */
	mlx_accel_core_connect(dev->core_ctx, dev->dqpn);
	return count;
}

static ssize_t mlx_tls_sgid_read(struct mlx_tls_dev *dev, char *buf)
{
	ssize_t ret = 0;
	union ib_gid sgid;

	// [BP]: TODO - We need to get a port number and index here...(assuming 0)
	/* [SR]: I think you just need GID-index. 0 is good (default GID). */
	ret = ib_query_gid(mlx_accel_core_get_ibdev(dev->core_ctx),
			mlx_accel_core_get_port_num(dev->core_ctx), 0, &sgid,
			NULL);
	if (ret) {
		pr_err("Failed to query gid got error %ld\n", ret);
		return -EIO;
	}

	return sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
			be16_to_cpu(((__be16 *) sgid.raw)[0]),
			be16_to_cpu(((__be16 *) sgid.raw)[1]),
			be16_to_cpu(((__be16 *) sgid.raw)[2]),
			be16_to_cpu(((__be16 *) sgid.raw)[3]),
			be16_to_cpu(((__be16 *) sgid.raw)[4]),
			be16_to_cpu(((__be16 *) sgid.raw)[5]),
			be16_to_cpu(((__be16 *) sgid.raw)[6]),
			be16_to_cpu(((__be16 *) sgid.raw)[7]));
}

static ssize_t mlx_tls_dgid_read(struct mlx_tls_dev *dev, char *buf)
{
	union ib_gid *dgid = &dev->core_ctx->dgid;
	return sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
			be16_to_cpu(((__be16 *) dgid->raw)[0]),
			be16_to_cpu(((__be16 *) dgid->raw)[1]),
			be16_to_cpu(((__be16 *) dgid->raw)[2]),
			be16_to_cpu(((__be16 *) dgid->raw)[3]),
			be16_to_cpu(((__be16 *) dgid->raw)[4]),
			be16_to_cpu(((__be16 *) dgid->raw)[5]),
			be16_to_cpu(((__be16 *) dgid->raw)[6]),
			be16_to_cpu(((__be16 *) dgid->raw)[7]));
}

static ssize_t mlx_tls_dgid_write(struct mlx_tls_dev *dev, const char *buf,
		size_t count)
{
	union ib_gid *dgid = &dev->core_ctx->dgid;
	int i = 0;
	sscanf(buf, "%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx\n",
			&(((__be16 *) dgid->raw)[0]),
			&(((__be16 *) dgid->raw)[1]),
			&(((__be16 *) dgid->raw)[2]),
			&(((__be16 *) dgid->raw)[3]),
			&(((__be16 *) dgid->raw)[4]),
			&(((__be16 *) dgid->raw)[5]),
			&(((__be16 *) dgid->raw)[6]),
			&(((__be16 *) dgid->raw)[7]));
	for (i = 0; i < 8; i++)
		((__be16 *) dgid->raw)[i] = cpu_to_be16(((u16 *)
			dgid->raw)[i]);
	return count;
}

/*********************************************************************
 *	This line seperates code that will be deleted in the final
 *	version(above) and code that will remain(below)
 * ********************************************************************/
/* [SR] TODO: Making sure the above comment will be cleaned up as well.*/

/* Code to communicate with the FPGA
*/

static void mlx_tls_wake_poll(struct mlx_tls_tcp_conn *conn)
{
	wake_up_interruptible_all(&conn->wq);
	/* things (e.g. epoll) may still wait on the original
	 * socket's wait queue */
	if (conn->sk == NULL || sk_sleep(conn->sk) == NULL)
		return;
	wake_up_interruptible_all(sk_sleep(conn->sk));
}

static void recv_cb(void *cb_arg, struct mlx_accel_core_dma_buf *buf)
{
	struct mlx_tls_dev *dev = cb_arg;
	struct generic_event *event = (struct generic_event *)buf->data;
	u32 stream_id = ntohl(event->stream_id);

	struct mlx_tls_tcp_conn *accel_conn;


	rcu_read_lock();
	accel_conn = find_conn_by_stream_id(dev, stream_id);
	if (accel_conn == NULL) {
		if (event->opcode == htonl(EVENT_SETUP_STREAM_RESPONSE)) {
			handle_setup_stream_response(dev, buf);
		} else {
			/* [SR] TODO: This can happen if the
			 * accel_conn was released between the time
			 * you sent the request for processing and the
			 * time the response reached you. You should
			 * handle this gracefully. Maybe you should
			 * maintain a reference count for the number
			 * of requests this socket still has in flight
			 * and delay the stream release until all
			 * requests to the FPGA were answered.
			 */
			pr_err("recv_cb: bad stream id %d\n", stream_id);
			kfree(buf);
		}
	} else {
		if (event->opcode == htonl(EVENT_FAST_PATH_DATA)) {
			/* should be the most common event */
			handle_fast_path_data(accel_conn, buf);
		} else {
			switch (event->opcode) {
			case htonl(EVENT_DATA_EVENT):
				handle_data_event(accel_conn, buf);
				break;
			case htonl(EVENT_PROCESS_TX_DATA_RESPONSE):
				handle_process_tx_data_event(accel_conn, buf);
				break;
			case htonl(EVENT_SETUP_STREAM_RESPONSE):
				pr_err("got EVENT_SETUP_STREAM_RESPONSE for an existing stream\n");
				kfree(buf);
				break;
			default:
				pr_err("got unknown event type %d\n", htonl(event->opcode));
				kfree(buf);
			}
		}
	}
	rcu_read_unlock();
}


/* Code to manage the mlx_tls_dev add/remove, when devices are added
 * or removed. */

/* must hold mlx_tls_mutex to call this function */
static struct mlx_tls_dev *find_mlx_tls_dev_by_netdev(struct net_device
		*netdev)
{
	struct mlx_tls_dev *dev;

	list_for_each_entry(dev, &driver.mlx_tls_devs, accel_dev_list) {
		struct ib_device *ib_dev = mlx_accel_core_get_ibdev(dev->core_ctx);
		struct net_device *ibdev_netdev =
			ib_dev->get_netdev(ib_dev, mlx_accel_core_get_port_num(dev->core_ctx));

		if (unlikely(!ibdev_netdev)) {
			pr_warn("find_mlx_tls_dev_by_netdev: Unable to get netdev for port %d. (Is it configured as IB instead of Ethernet?)\n", mlx_accel_core_get_port_num(dev->core_ctx));
			continue;
		}

		dev_put(ibdev_netdev);
		if (netdev == ibdev_netdev)
			return dev;
	}

	return NULL;
}

static int alloc_mlx_tls_dev(struct mlx_tls_dev **dev,
		struct mlx_accel_core_ctx *ctx)
{
	int ret = 0;
	struct mlx_tls_dev *accel_dev = NULL;
	struct kobject *parent = mlx_accel_core_kobj_parent_get(ctx);

	*dev = NULL;
	accel_dev = kzalloc(sizeof(struct mlx_tls_dev), GFP_KERNEL);
	if (!accel_dev) {
		*dev = NULL;
		/* [SR] TODO: Are you leaking a core-context here?
		 * [BP]: The core-context will be released by mlx_accel_core
		 * when either the client exits or the device is removed.
		 */
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&accel_dev->rx_handlers);
	INIT_LIST_HEAD(&accel_dev->tx_handlers);
	spin_lock_init(&accel_dev->accel_tcp_conns_lock);
	INIT_LIST_HEAD(&accel_dev->accel_tcp_conns);
	INIT_LIST_HEAD(&accel_dev->accel_dev_list);
	accel_dev->core_ctx = ctx;


	/* [BP]: TODO: is this the parent we want? do we want to sit under the
	 * port? will the core have a sysfs? will we want to sit under it?
	 */
	ret = kobject_init_and_add(&accel_dev->kobj, &mlx_tls_dev_type,
			parent,
			"%s",
			"accel_dev");
	if (ret) {
		pr_err("Got error from kobject_init_and_add\n");
		mlx_accel_core_release(ctx);
		kfree(accel_dev);
		return ret;
	}

	*dev = accel_dev;

	mutex_lock(&mlx_tls_mutex);
	list_add(&accel_dev->accel_dev_list, &driver.mlx_tls_devs);
	mutex_unlock(&mlx_tls_mutex);

	return ret;
}

/* [SR]: TODO: The basic accelerator device init should be part of the core,
 * as it will also create a CR-space QP and other stuff. The
 * accelerator core should call the clients, including us, when a new
 * device is discovered.
 * [BP]: Eventually the core could create the QP using the I2C,
 * and we could query the core when we need a netdev, instead of being called
 * as a client.
 * But, currently we must rely on a user space tcp connection for establishing
 * a QP. For this reason there must be a dependency between core and accel.
 *
 * [SR]: Why not move the sysfs uglyness for connection creation to the core?
 *       Can help other implementation that will want to do the same with simulator.
 *
 * Also, the function code here seems like an empty call jump,
 * consider killing the entire function.
 */
void mlx_tls_add_one(struct mlx_accel_core_device *accel_device)
{
	struct net_device *netdev = NULL;
	struct mlx_tls_dev *dev = NULL;
	int ret = 0;

	pr_info("mlx_tls_add_one called\n");

	ret = alloc_mlx_tls_dev(&accel_dev, ctx);
	if (ret) {
		pr_err("Got error while creating mlx_tls_dev %d\n", ret);
		return;
	}
}

/* [BP]: We need to release all accelerated tcp connections using this
 * accel_dev
 */
static void mlx_tls_dev_release(struct kobject *kobj)
{
	struct mlx_tls_dev *dev = container_of(kobj, struct mlx_tls_dev,
			kobj);
	struct mlx_tls_tcp_conn* accel_conn = NULL;

	pr_info("mlx_tls_dev_release called\n");
	/*
	 * [BP]: Review this code after deciding on how to use rx/tx handlers
	 * with multiple offload types (ipsec + tls)
	 */
	if (!list_empty(&dev->rx_handlers)) {
		pr_err("mlx_tls_dev_release - there are rx_handlers still running!\n");
		return;
	}

	if (!list_empty(&dev->tx_handlers)) {
		pr_err("mlx_tls_dev_release - there are tx_handlers still running!\n");
		return;
	}

	kfree(dev);
}

/* Must hold mlx_tls_mutex to call this function.
 * Assumes that dev->core_ctx is destroyed be the caller
 */
static void mlx_tls_free(struct mlx_tls_dev *dev)
{
	list_del(&dev->accel_dev_list);
	kobject_put(&dev->kobj);
}

static void mlx_tls_remove_one(struct mlx_accel_core_ctx *ctx)
{
	struct mlx_tls_dev *dev, *tmp;

	pr_info("mlx_tls_remove_one called\n");
	mutex_lock(&mlx_tls_mutex);

	list_for_each_entry_safe(dev, tmp, &driver.mlx_tls_devs, accel_dev_list) {
		if (ctx->ibdev == mlx_accel_core_get_ibdev(dev->core_ctx)) {
			mlx_tls_free(dev);
		}
	}

	mutex_unlock(&mlx_tls_mutex);
}


static void mlx_tls_unregister_tx_handler (struct net_device *netdev,
		struct handler_context *context)
{
	mlx_unregister_tx_handler(netdev);

	put_net(context->net);
	list_del(&context->list);

	kfree(context);
}

static void mlx_tls_unregister_rx_handler (struct net_device *netdev,
		struct handler_context *context)
{
	rtnl_lock();
	netdev_rx_handler_unregister(netdev);
	rtnl_unlock();

	put_net(context->net);
	list_del(&context->list);

	kfree(context);
}

static int mlx_tls_netdev_event(struct notifier_block *this, unsigned long
		event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct mlx_tls_dev *accel_dev = NULL;

	if (!netdev)
		goto out;

	pr_info("mlx_tls_netdev_event: %lu\n", event);

	/* We are interested only in net devices going down */
	if (event != NETDEV_UNREGISTER)
		goto out;

	/* Take down all connections using a netdev that is going down */
	accel_dev = find_mlx_tls_dev_by_netdev(netdev);
	if (!accel_dev)
		goto out;

	/* [BP]: TODO Remove matching connection */
	pr_info("Removing netdevice named: %s\n",
			netdev->name);
	mlx_tls_free(accel_dev);

out:
	return NOTIFY_DONE;
}

static struct notifier_block mlx_tls_netdev_notifier = {
	.notifier_call = mlx_tls_netdev_event,
};

static int __init mlx_tls_init(void)
{
	int err = 0;

	INIT_LIST_HEAD(&driver.mlx_tls_devs);

	err = register_netdevice_notifier(&mlx_tls_netdev_notifier);
	if (err) {
		pr_err("mlx_tls_init error in register_netdevice_notifier %d\n",
			err);
		goto out;
	}

	mlx_accel_core_client_register(&mlx_tls_client);

	return 0;

out:
	return err;
}

static void __exit mlx_tls_exit(void)
{
	mlx_accel_core_client_unregister(&mlx_tls_client);
	unregister_netdevice_notifier(&mlx_tls_netdev_notifier);
}

module_init(mlx_tls_init);
module_exit(mlx_tls_exit);


