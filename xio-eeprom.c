/*
 * xio-eeprom.c
 * A tool to access the EEPROM of Texas Instruments XIOxxxx devices in Linux.
 *
 * compile with:  make xio-eeprom
 *
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <argp.h>

#define PCI_DEVICES_DIR "/sys/bus/pci/devices"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define PCI_CFG_I2C_DATA	0xb0
#define PCI_CFG_I2C_WORD_ADDR	0xb1
#define PCI_CFG_I2C_SLAVE_ADDR	0xb2
#define PCI_CFG_I2C_CTRL_STATUS	0xb3

#define I2C_WRITE		0x00
#define I2C_READ		0x01
#define EEPROM_SLAVE_ADDR	0xa0

#define I2C_ROM_ERR		0x01
#define I2C_SB_ERR		0x02
#define I2C_SBTEST		0x04
#define I2C_SBDETECT		0x08
#define I2C_ROMBUSY		0x10
#define I2C_REQBUSY		0x20
#define I2C_PROT_SEL		0x80

struct device_properties {
	int id;
	int eeprom_size;
	int guid_offset;
	const char *name;
};

static const struct device_properties xio_devices[] = {
	{ .id = 0x8231, .eeprom_size = 33, .guid_offset =   -1, .name = "XIO2000"         },
	{ .id = 0x8231, .eeprom_size = 58, .guid_offset = 0x29, .name = "XIO2200"         },
	{ .id = 0x8232, .eeprom_size = 82, .guid_offset =   -1, .name = "XIO3130"         },
	{ .id = 0x823e, .eeprom_size = 59, .guid_offset = 0x29, .name = "XIO2213/XIO2221" },
	{ .id = 0x8240, .eeprom_size = 40, .guid_offset =   -1, .name = "XIO2001"         },
};

static enum {
	ACTION_NONE, ACTION_VIEW, ACTION_DUMP, ACTION_PROGRAM, ACTION_UPDATE, ACTION_VIEW_GUID
} arg_action = ACTION_NONE;
static const char *arg_eeprom_file = NULL;
static const char *arg_guid = NULL;
static const char *arg_name_file = NULL;

static struct dirent **devices;
static int num_devices;
static const struct device_properties *device_properties = NULL;

static uint8_t guid[8];

static int config_fd;

static void parse_guid(struct argp_state *state)
{
	int i;
	unsigned int buf[8];

	if (strlen(arg_guid) != 16)
		argp_error(state, "the GUID value must have 16 digits");
	for (i = 0; i < 16; i++) {
		if (!isxdigit(arg_guid[i]))
			argp_error(state, "the GUID value must contain only hexadecimal digits");
	}
	sscanf(arg_guid, "%2x%2x%2x%2x%2x%2x%2x%2x",
	       &buf[3], &buf[2], &buf[1], &buf[0], &buf[7], &buf[6], &buf[5], &buf[4]);
	for (i = 0; i < 8; i++)
		guid[i] = buf[i];
}

static error_t parse_option(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		arg_action = ACTION_VIEW;
		break;
	case 'd':
		arg_action = ACTION_DUMP;
		arg_eeprom_file = arg;
		break;
	case 'p':
		arg_action = ACTION_PROGRAM;
		arg_eeprom_file = arg;
		break;
	case 'u':
		arg_action = ACTION_UPDATE;
		break;
	case 'g':
		arg_guid = arg;
		parse_guid(state);
		break;
	case 'L':
		arg_action = ACTION_VIEW_GUID;
		break;
	case ARGP_KEY_ARG:
		if (arg_name_file != NULL)
			argp_usage(state);
		arg_name_file = arg;
		break;
	case ARGP_KEY_END:
		if (arg_action == ACTION_NONE)
			argp_error(state, "one of --view/--dump/--program/--update/--view-guid must be specified");
		if (arg_action == ACTION_UPDATE && arg_guid == NULL)
			argp_error(state, "updating requires a GUID value");
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* reads a number from a sysfs text file */
static int read_from_file(const struct dirent *dir, const char *file)
{
	int fd, value;
	char *filename;
	ssize_t bytes;
	char buf[32];

	asprintf(&filename, "%s/%s/%s", PCI_DEVICES_DIR, dir->d_name, file);
	fd = open(filename, O_RDONLY);
	free(filename);
	if (fd == -1)
		return -1;
	bytes = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	buf[sizeof(buf) - 1] = '\0';
	if (bytes > 0 && sscanf(buf, "%i", &value) == 1)
		return value;
	else
		return -1;
}

static bool detect_2200_ohci(const struct dirent *parent_dir)
{
	bool ohci_found = false;
	char *parent_dir_name;
	DIR *dir;
	const struct dirent *dev_dir;

	asprintf(&parent_dir_name, "%s/%s", PCI_DEVICES_DIR, parent_dir->d_name);
	dir = opendir(parent_dir_name);
	if (dir) {
		for (;;) {
			dev_dir = readdir(dir);
			if (dev_dir == NULL)
				break;
			if (dev_dir->d_type != DT_DIR || strlen(dev_dir->d_name) < 10)
				continue;
			ohci_found = read_from_file(dev_dir, "vendor") == 0x104c &&
				read_from_file(dev_dir, "device") == 0x8235;
			if (ohci_found)
				break;
		}
		closedir(dir);
	}
	free(parent_dir_name);
	return ohci_found;
}

/* checks if the directory is for a XIO chip */
static int xio_filter(const struct dirent *dev_dir)
{
	int id;
	size_t i;

	/* take only the first device found */
	if (device_properties != NULL)
		return 0;

	if (dev_dir->d_name[0] == '.')
		return 0;

	id = read_from_file(dev_dir, "vendor");
	if (id != 0x104c /* TI */)
		return 0;

	id = read_from_file(dev_dir, "device");
	for (i = 0; i < ARRAY_SIZE(xio_devices); i++)
		if (xio_devices[i].id == id) {
			device_properties = &xio_devices[i];
			/* special case: a XIO2000 with 1394 OHCI is a XIO2200 */
			if (device_properties->id == 0x8231 && detect_2200_ohci(dev_dir))
				device_properties++;
			return 1;
		}
	return 0;
}

static void open_device(struct dirent *dev_dir)
{
	char *file_name;

	asprintf(&file_name, "%s/%s/%s", PCI_DEVICES_DIR, dev_dir->d_name, "config");
	config_fd = open(file_name, O_RDWR);
	if (config_fd == -1) {
		const char *hint = "";
		if (errno == EACCES)
			hint = "This tool needs root privileges to access the hardware.\n";
		fprintf(stderr, "cannot open %s: %s\n%s", file_name, strerror(errno), hint);
		exit(1);
	}
	free(file_name);
}

static uint8_t read_pci_config(int reg)
{
	uint8_t value;
	ssize_t bytes;

	bytes = pread(config_fd, &value, 1, reg);
	if (bytes == 0) {
		fprintf(stderr, "This tool needs root privileges to access the hardware.\n");
		exit(1);
	} else if (bytes < 0) {
		perror("cannot read PCI configuration register");
		exit(1);
	}
	return value;
}

static void write_pci_config(int reg, uint8_t value)
{
	ssize_t bytes;

	bytes = pwrite(config_fd, &value, 1, reg);
	if (bytes == 0) {
		fprintf(stderr, "This tool needs root privileges to access the hardware.\n");
		exit(1);
	} else if (bytes < 0) {
		perror("cannot write PCI configuration register");
		exit(1);
	}
}

static uint8_t wait_for_i2c(void)
{
	int timeout;
	uint8_t status;

	for (timeout = 0; timeout < 10; timeout++) {
		status = read_pci_config(PCI_CFG_I2C_CTRL_STATUS);
		if (!(status & I2C_SBDETECT)) {
			fprintf(stderr, "no serial EEPROM detected\n");
			exit(1);
		}
		if (status & I2C_ROMBUSY)
			usleep(100000);
		else if (status & I2C_REQBUSY)
			usleep(1000);
		else
			break;
	}
	if (status & (I2C_ROMBUSY | I2C_REQBUSY)) {
		fprintf(stderr, "timeout: EEPROM is busy\n");
		exit(1);
	}
	return status;
}

static void wait_for_i2c_init(void)
{
	uint8_t status = wait_for_i2c();
	if (status & (I2C_ROM_ERR | I2C_SB_ERR | I2C_SBTEST | I2C_PROT_SEL))
		write_pci_config(PCI_CFG_I2C_CTRL_STATUS,
				 status & ~(I2C_SBTEST | I2C_PROT_SEL));
}

static uint8_t read_eeprom(int offset)
{
	wait_for_i2c_init();

	write_pci_config(PCI_CFG_I2C_WORD_ADDR, offset);
	write_pci_config(PCI_CFG_I2C_SLAVE_ADDR, I2C_READ | EEPROM_SLAVE_ADDR);

	if (wait_for_i2c() & I2C_SB_ERR) {
		fprintf(stderr, "serial bus error\n");
		exit(1);
	}

	return read_pci_config(PCI_CFG_I2C_DATA);
}

static void write_eeprom(int offset, uint8_t value)
{
	wait_for_i2c_init();

	write_pci_config(PCI_CFG_I2C_DATA, value);
	write_pci_config(PCI_CFG_I2C_WORD_ADDR, offset);
	write_pci_config(PCI_CFG_I2C_SLAVE_ADDR, I2C_WRITE | EEPROM_SLAVE_ADDR);
	usleep(10000);

	if (wait_for_i2c() & I2C_SB_ERR) {
		fprintf(stderr, "serial bus error\n");
		exit(1);
	}
}

static void do_view(void)
{
	int size, offset;

	size = (device_properties->eeprom_size + 15) & ~15;
	for (offset = 0; offset < size; offset++) {
		if ((offset % 16) == 0)
			printf("%04x:", offset);
		printf(" %02x", read_eeprom(offset));
		if ((offset % 16) == 15)
			putchar('\n');
	}
}

static void do_view_guid(void)
{
	uint8_t buf[8];
	int i;

	if (device_properties->guid_offset < 0) {
		fprintf(stderr, "the %s does not have a GUID\n", device_properties->name);
		exit(1);
	}
	for (i = 0; i < 8; i++)
		buf[i] = read_eeprom(device_properties->guid_offset + i);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x\n", buf[3], buf[2], buf[1], buf[0], buf[7], buf[6], buf[5], buf[4]);
}

static void do_dump(void)
{
	uint8_t buf[0x100];
	int offset;
	FILE *f;
	uint8_t mask;

	assert((int)sizeof(buf) >= device_properties->eeprom_size);
	for (offset = 0; offset < device_properties->eeprom_size; offset++)
		buf[offset] = read_eeprom(offset);

	f = fopen(arg_eeprom_file, "w");
	if (!f) {
		perror(arg_eeprom_file);
		exit(1);
	}
	fprintf(f, "; EEPROM data dump for %s\n", device_properties->name);
	fprintf(f, ";\n");
	fprintf(f, "; reg  value       binary\n");
	fprintf(f, "; ---  -----   ----------\n");
	for (offset = 0; offset < device_properties->eeprom_size; offset++) {
		fprintf(f, "   %02x   0x%02x  ;0b", offset, buf[offset]);
		for (mask = 0x80; mask != 0; mask >>= 1)
			fputc(buf[offset] & mask ? '1' : '0', f);
		fputc('\n', f);
	}
	fclose(f);
}

static void do_program(void)
{
	FILE *f;
	char line[512];
	char value_str[256];
	char *p;
	uint8_t data[0x100];
	uint8_t data_type[0x100] = { 0 };
	unsigned int offset, count;
	int line_number, i, chars;
	uint8_t check;
	bool any_error;

	f = fopen(arg_eeprom_file, "r");
	if (!f) {
		perror(arg_eeprom_file);
		exit(1);
	}
	line_number = 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		line_number++;
		p = line;
		while (isspace(*p))
			p++;
		if (*p == ';' || *p == '\0')
			continue;
		if (sscanf(p, "%x", &offset) != 1 || offset >= 0x100) {
			fprintf(stderr, "line %i: invalid register address\n", line_number);
			exit(1);
		}
		sscanf(p, "%x%n", &offset, &chars);
		p += chars;
		if (data_type[offset] != 0) {
			fprintf(stderr, "line %i: duplicate register address\n", line_number);
			exit(1);
		}
		if (sscanf(p, "%255s", value_str) != 1) {
			fprintf(stderr, "line %i: no value\n", line_number);
			exit(1);
		}
		if (tolower(value_str[0]) == 'x' && tolower(value_str[1]) == 'x') {
			fprintf(stderr, "automatic serial numbers not yet supported\n");
			exit(1);
		} else {
			if (value_str[0] == '0' && tolower(value_str[1]) == 'b') {
				data[offset] = 0;
				for (p = &value_str[2]; *p != '\0'; p++) {
					data[offset] <<= 1;
					switch (*p) {
					case '0':
						break;
					case '1':
						data[offset] |= 1;
						break;
					default:
						fprintf(stderr, "line %i: invalid binary value\n", line_number);
						exit(1);
					}
				}
			} else {
				if (sscanf(value_str, "%i", &i) != 1) {
					fprintf(stderr, "line %i: invalid data byte\n", line_number);
					exit(1);
				}
				data[offset] = i;
			}
			data_type[offset] = 1;
		}
	}
	fclose(f);

	count = 0;
	for (i = 0; i < 0x100; i++) {
		if (data_type[i]) {
			write_eeprom(i, data[i]);
			count++;
		}
	}
	fprintf(stderr, "%u bytes written\n", count);
	any_error = false;
	for (i = 0; i < 0x100; i++) {
		if (data_type[i]) {
			check = read_eeprom(i);
			if (check != data[i]) {
				any_error = true;
				fprintf(stderr, "byte at offset %#x was not written correctly (0x%02x != 0x%02x)\n",
					i, check, data[i]);
			}
		}
	}
	fprintf(stderr, "%u bytes checked\n", count);
	if (any_error)
		exit(1);
}

static void do_update(void)
{
	int i;
	uint8_t check;
	bool any_error = false;

	if (device_properties->guid_offset < 0) {
		fprintf(stderr, "the %s does not have a GUID\n", device_properties->name);
		exit(1);
	}
	for (i = 0; i < 8; i++)
		write_eeprom(device_properties->guid_offset + i, guid[i]);
	fprintf(stderr, "%u bytes written\n", 8);

	for (i = 0; i < 8; i++) {
		check = read_eeprom(device_properties->guid_offset + i);
		if (check != guid[i]) {
			any_error = true;
			fprintf(stderr, "byte at offset %#x was not written correctly (0x%02x != 0x%02x)\n",
				device_properties->guid_offset + i, check, guid[i]);
		}
	}
	fprintf(stderr, "%u bytes checked\n", 8);
	if (any_error)
		exit(1);
}

int main(int argc, char *argv[])
{
	static const struct argp_option options[] = {
		{ .name = "view",      .key = 'v',                            .doc = "view EEPROM contents" },
		{ .name = "dump",      .key = 'd', .arg = "output_file",      .doc = "dump EEPROM contents" },
		{ .name = "program",   .key = 'p', .arg = "input_file",       .doc = "program the EEPROM" },
		{ .name = "update",    .key = 'u',                            .doc = "program only the GUID" },
		{ .name = "guid",      .key = 'g', .arg = "XXXXXXXXXXXXXXXX", .doc = "program this GUID value" },
		{ .name = "view-guid", .key = 'L',                            .doc = "view GUID from EEPROM" },
		{ 0 }
	};
	static const struct argp argp = {
		.options = options,
		.parser = parse_option,
#if 0
		.args_doc = "[register_name_file]",
#endif
		.doc = "Access the EEPROM of Texas Instruments XIOxxxx devices.",
	};

	argp_program_version = "0.1";
	argp_program_bug_address = "<https://github.com/cladisch/xio-eeprom/issues>";
	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	num_devices = scandir(PCI_DEVICES_DIR, &devices, xio_filter, alphasort);
	if (num_devices == -1) {
		fprintf(stderr, "cannot scan %s: %s\n", PCI_DEVICES_DIR, strerror(errno));
		return 1;
	}

	if (num_devices == 0) {
		fprintf(stderr, "no XIO device found\n");
		return 1;
	}
#if 0
	if (num_devices > 1) {
		/* select one ... */
	}
#endif

	open_device(devices[0]);

	switch (arg_action) {
	case ACTION_VIEW:
	default:
		do_view();
		break;
	case ACTION_DUMP:
		do_dump();
		break;
	case ACTION_PROGRAM:
		do_program();
		break;
	case ACTION_UPDATE:
		do_update();
		break;
	case ACTION_VIEW_GUID:
		do_view_guid();
		break;
	}

	return 0;
}
