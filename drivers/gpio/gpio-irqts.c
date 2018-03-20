/*
 * GPIO interrupt timestamp driver
 * Copyright (C) 2018 Siim Meerits
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/gpio.h>
#include <linux/time.h>

/* Macros */
#define IRQTS_DEVICE_NAME "gpio_ts"
#define IRQTS_CLASS_NAME "gpio_irqts"

/* Declarations */
static ssize_t irqts_read(struct file *filep, char *buffer, size_t len,
	loff_t *offset);
static ssize_t irqts_write(struct file *filep, const char *buffer, size_t len,
	loff_t *offset)
static int irqts_open(struct inode *inodep, struct file *filep);
static int irqts_release(struct inode *inodep, struct file *filep);
static irq_handler_t irqts_handler(unsigned int irq, void *dev_id,
	struct pt_regs *regs);

/* Character device */
static DEFINE_MUTEX(irqts_mutex);
static int irqts_major;
static struct class* irqts_class = NULL;
static struct device* irqts_device = NULL;
static struct file_operations irqts_fops = {
	.read = irqts_read,
	.write = irqts_write,
	.open = irqts_open,
	.release = irqts_release,
};

/* Pin and interrupt */
static struct timespec irqts_ts = {0, 0};
static unsigned int irqts_pin = 0;
static unsigned int irqts_irq = 0;

/* Character device operations */
static ssize_t irqts_read(struct file *filep, char *buffer, size_t len,
	loff_t *offset)
{
	if (len != sizeof(irqts_ts))
		return 0;
	if (irqts_ts.tv_sec == 0 && irqts_ts.tv_nsec == 0)
		return 0;

	/* Copy */
	mutex_lock(&irqts_mutex);
	copy_to_user(buffer, &irqts_ts, len);
	irqts_ts = {0, 0};
	mutex_unlock(&irqts_mutex);

	return sizeof(irqts_ts);
}

static ssize_t irqts_write(struct file *filep, const char *buffer, size_t len,
	loff_t *offset)
{
	unsigned int new_pin = 0, new_irq = 0;
	ssize_t result = 0;

	/* Only a single unsigned int is accepted */
	if (len < sizeof(new_pin))
		return 0;
	result = copy_from_user(&new_pin, buffer, sizeof(new_pin));
	if (result < sizeof(new_pin))
		return 0;

	/* Mutex */
	mutex_lock(&irqts_mutex);

	/* Release pin */
	if (irqts_pin != 0) {
		free_irq(irqts_irq, NULL);
		gpio_unexport(irqts_pin);
		gpio_free(irqts_pin);
		irqts_ts = {0, 0};
		irqts_pin = 0;
		irqts_irq = 0;
	}

	/* New pin to set up */
	if (new_pin) {
		/* Set up pin */
		if (!gpio_is_valid(new_pin)) {
			printk(KERN_INFO "%s: invalid pin %d\n", THIS_MODULE->name,
				new_pin);
			result = -ENODEV;
			goto err_pin;
		}

		gpio_request(new_pin, "sysfs");
		gpio_direction_input(new_pin);
		gpio_set_debounce(new_pin, 1000); // 1 ms
		gpio_export(new_pin, false);

		new_irq = gpio_to_irq(new_pin);
		result = request_irq(new_irq, (irq_handler_t) irqts_handler,
			IRQF_TRIGGER_RISING, "irqts_handler", NULL);
		if (result) {
			printk(KERN_ALERT "%s: failed to set up interrupt\n",
				THIS_MODULE->name);
			goto err_irq;
		}

		irqts_pin = new_pin;
		irqts_irq = new_irq;
	}

	/* Mutex */
	mutex_unlock(&irqts_mutex);
	return sizeof(irqts_pin);

err_irq:
	gpio_unexport(irqts_pin);
	gpio_free(irqts_pin);

err_pin:
	mutex_unlock(&irqts_mutex);
	return result;
}

static int irqts_open(struct inode *inodep, struct file *filep)
{
   return 0;
}

static int irqts_release(struct inode *inodep, struct file *filep)
{
   return 0;
}

/* Interrupt handler */
static irq_handler_t irqts_handler(unsigned int irq, void *dev_id,
	struct pt_regs *regs)
{
	struct timespec ts = {0, 0};

	/* Timestamp */
	local_irq_disable();
	getnstimeofday(&ts);
	local_irq_enable();

	/* Mutex */
	mutex_lock(&irqts_mutex);
	irqts_ts = ts;
	mutex_unlock(&irqts_mutex);

	/*
	printk(KERN_INFO "%s: interrupt at %lld.%.9ld\n", THIS_MODULE->name,
		(long long)ts.tv_sec, ts.tv_nsec);
	*/

	return (irq_handler_t) IRQ_HANDLED;
}

/* Module init and exit */
static int __init irqts_init(void)
{
	unsigned int result = 0;

	/* Logging */
	printk(KERN_INFO "%s: GPIO irqts driver\n", THIS_MODULE->name);

	/* Mutex */
	mutex_init(&irqts_mutex);

	/* Character device */
	irqts_major = register_chrdev(0, IRQTS_DEVICE_NAME, &irqts_fops);
	if (irqts_major < 0) {
		printk(KERN_ALERT "%s: failed to register a major number\n",
			THIS_MODULE->name);
		result = irqts_major;
		goto err_major;
	}

	irqts_class = class_create(THIS_MODULE, IRQTS_CLASS_NAME);
	if (IS_ERR(irqts_class)) {
		printk(KERN_ALERT "%s: failed to register device class\n",
			THIS_MODULE->name);
		result = PTR_ERR(irqts_class);
		goto err_class;
	}

	irqts_device = device_create(irqts_class, NULL,
		MKDEV(irqts_major, 0), NULL, IRQTS_DEVICE_NAME);
	if (IS_ERR(irqts_device)) {
		printk(KERN_ALERT "%s: failed to create the device\n",
			THIS_MODULE->name);
		result = PTR_ERR(irqts_device);
		goto err_device;
	}

	return result;

err_device:
	class_unregister(irqts_class);
	class_destroy(irqts_class);

err_class:
	unregister_chrdev(irqts_major, IRQTS_DEVICE_NAME);

err_major:
	mutex_destroy(&irqts_mutex);
	return result;
}

static void __exit irqts_exit(void)
{
	/* Release pin */
	if (irqts_pin) {
		free_irq(irqts_irq, NULL);
		gpio_unexport(irqts_pin);
		gpio_free(irqts_pin);
	}

	/* Character device */
	device_destroy(irqts_class, MKDEV(irqts_major, 0));
	class_unregister(irqts_class);
	class_destroy(irqts_class);
	unregister_chrdev(irqts_major, IRQTS_DEVICE_NAME);

	/* Mutex */
	mutex_destroy(&irqts_mutex);
}

module_init(irqts_init);
module_exit(irqts_exit);

MODULE_AUTHOR("Siim Meerits <siim@yutani.ee>");
MODULE_DESCRIPTION("GPIO interrupt timestamp driver");
MODULE_LICENSE("GPL");
