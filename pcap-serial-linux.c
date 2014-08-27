/* 
 * pcap_serial_linux.c: Packet capture using serial interfaces.
 *
 * Author: Thomas W. Edgar
 *
 * Created on February 4, 2010, 6:52 PM
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcap-int.h"
#include "pcap-serial-linux.h"
#include "pcap/serial.h"
#include "pcap-sscp-linux.h"
#include "pcap-dnp3-linux.h"
#include "pcap-modbus-linux.h"


#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <byteswap.h>
#include <time.h>
#include <pthread.h>

#define SERIAL_IFACE "tty"
#define DEV_DIR "/dev"
#define SERIAL_LINE_LEN 4096

/* forward declaration */
static int serial_activate(pcap_t *);
static int serial_read_linux(pcap_t *, int, pcap_handler, u_char *);
static int serial_inject_linux(pcap_t *, const void *, size_t);
static int serial_setfilter_linux(pcap_t *, struct bpf_program *);
static int serial_setdirection_linux(pcap_t *, pcap_direction_t );
static int serial_stats_linux(pcap_t *, struct pcap_stat *);
static int serial_set_datalink(pcap_t *, int);
void *execute_parsing_thread_linux(void*);
static int serial_start_thread(pcap_t *handle);
long get_time_millis(void);
int buffer_get_space_size(pcap_t *, int, int);
int buffer_get_packet_len(pcap_t *, int, int);
void buffer_add_data(pcap_t *, unsigned char *, int);
void buffer_remove_data(pcap_t *, int, unsigned char *, int);
int append_to_queue(pcap_t *, pcap_serial_packet_pointer *);
pcap_serial_packet_pointer *remove_from_queue(pcap_t *);
pcap_serial_packet_pointer *peek_on_queue(pcap_t *);

static u_long timeout;

/* function to detect if a physical port exists */
int
is_serial_port(const char* device)
{
    int fd;
    int ret = 1;
    struct termios t;

    fd = open(device, O_RDWR);
    if(fd < 0)
        return 0;

    if(tcgetattr(fd, &t))
        ret = 0;
    close(fd);
    return ret;
}

int
serial_platform_finddevs(pcap_if_t **alldevsp, char *err_str)
{
	struct dirent* data;
	int ret = 0;
	DIR* dir;
	int n;
	char* name;
	size_t len;

	/* try scanning sysfs usb bus directory */
	dir = opendir(DEV_DIR);
	if (dir != NULL) {
		while ((ret == 0) && ((data = readdir(dir)) != 0)) {
			name = data->d_name;

			if (strncmp(name, "ttyS", 4) == 0) {
                            //udev automatically creates ttyS0-3 so must check
                            //for actual port before adding to list
                            if(is_serial_port(name)) {
                                char dev_descr[30];
                                snprintf(dev_descr, 30, "Serial bus number %s", name);

                               if ( pcap_add_if(alldevsp, name, 0,
                                    dev_descr, err_str) < 0) {
                                   ret = -1;
                               }

                            }
                        }
                        else if(strncmp(name, "ttyUSB", 6) == 0) {
                            char dev_descr[30];
                            snprintf(dev_descr, 30, "Serial bus number usb%s", name);

                            if ( pcap_add_if(alldevsp, name, 0,
                                dev_descr, err_str) < 0) {
                                ret = -1;
                            }
                        }
		}

		closedir(dir);
		return ret;
	}
	return 0;
}

pcap_t *
serial_create(const char *device, char *ebuf)
{
    	pcap_t *p;

	p = pcap_create_common(device, ebuf);
	if (p == NULL)
		return (NULL);

	p->activate_op = serial_activate;
        p->opt.baud = -1;
        p->opt.databits = -1;
        p->opt.parity = -1;
        p->opt.stopbits = -1;

	return (p);
}

/* I'm following what pcap-usb-linux does here since it seems to fit most closely
 * with the serial type of interface*/
static int
serial_activate(pcap_t* handle)
{

	char 	full_path[SERIAL_LINE_LEN];
        int len = 0;
        int dlt_index = 0;
        struct termios config;

        /* Check for if serial parameters are set before moving forward */
        if(handle->opt.baud == -1 ||
           handle->opt.databits == -1 ||
           handle->opt.stopbits == -1 ||
           handle->opt.parity == -1) {
            snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"Serial port configuration parameters are not set for %s", handle->opt.source);
            return PCAP_ERROR;
        }
	/* Initialize some components of the pcap structure. */
	handle->bufsize = handle->snapshot;
	handle->offset = 0;
        /* Need to request for this DLT from libpcap group */
	handle->linktype = DLT_SERIAL;
	handle->read_op = serial_read_linux;

	handle->stats_op = serial_stats_linux;
	//handle->md.ifindex = dev_id;
	handle->inject_op = serial_inject_linux;
	handle->setfilter_op = serial_setfilter_linux;
	handle->setdirection_op = serial_setdirection_linux;
	handle->set_datalink_op = serial_set_datalink;
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = pcap_setnonblock_fd;

        /* Set up the data link options */
        if((handle->dlt_list = (u_int*)malloc(255*sizeof(u_int)))== NULL) {
           (void)snprintf(handle->errbuf, sizeof(handle->errbuf), "malloc: %s", pcap_strerror(errno));
            return (-1);
        }

        handle->dlt_list[dlt_index++] = DLT_SERIAL;
        handle->dlt_list[dlt_index++] = DLT_DNP3;
        handle->dlt_list[dlt_index++] = DLT_MODBUS;
        handle->dlt_list[dlt_index++] = DLT_SSCP;
        handle->dlt_count = dlt_index;
        /* The default dl_type is serial.  All other choices must be forced
         * via a call to pcap_set_datalink */
        handle->linktype = DLT_SERIAL;


	/*get serial index from device name
         may need to change this for ttyUSB, don't exactly understand what this
         is used for right now*/
        len = strlen(handle->opt.source);
        if(!isdigit(handle->opt.source[len-1])) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"Can't get Serial index from %s", handle->opt.source);
		return PCAP_ERROR;
	}
        handle->md.ifindex = handle->opt.source[len-1];

        
        /*open the serial interface for reading*/
        snprintf(full_path, SERIAL_LINE_LEN, DEV_DIR"/%s", handle->opt.source);
        printf("Opening serial port %s.\n", full_path);
        handle->fd = open(full_path, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (handle->fd < 0) {
            perror(full_path);
            return -1;
        }

        /* Create termios and set port settings */
        switch (handle->opt.baud) {
            case 300: config.c_cflag = B300;
                break;
            case 600: config.c_cflag = B600;
                break;
            case 1200: config.c_cflag = B1200;
                break;
            case 2400: config.c_cflag = B2400;
                break;
            case 4800: config.c_cflag = B4800;
                break;
            case 9600: config.c_cflag = B9600;
                break;
            case 19200: config.c_cflag = B19200;
                break;
            case 38400: config.c_cflag = B38400;
                break;
        }
        switch (handle->opt.databits) {
            case 8: config.c_cflag |= CS8;
                break;
            case 7: config.c_cflag |= CS7;
                break;
            case 6: config.c_cflag |= CS6;
                break;
            case 5: config.c_cflag |= CS5;
                break;
        }
        switch (handle->opt.stopbits) {
            case 1: config.c_cflag |= 0;
                break;
            case 2: config.c_cflag |= CSTOPB;
                break;
        }
        switch (handle->opt.parity) {
            case 0:
                break; // none
            case 1: config.c_cflag |= PARENB | PARODD;
                break; // odd
            case 2: config.c_cflag |=PARENB;
                break; // even
        }
        config.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
            | INLCR | IGNCR | ICRNL | IXON);
        config.c_oflag &= ~OPOST;
        config.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        config.c_cc[VMIN] = 1;
        config.c_cc[VTIME] = 1;
        config.c_cflag |= CLOCAL | CREAD;
            // Save current port settings
        if ((ioctl(handle->fd, TIOCEXCL) == -1) || /* Prevent multiple opens on same portID */
            (tcflush(handle->fd, TCIFLUSH) == -1) || /* clean port */
            (tcsetattr(handle->fd, TCSANOW, &config) < 0)) /* activate the settings port */
            return PCAP_ERROR;
        fcntl(handle->fd, F_SETFL, FASYNC);
        signal(SIGIO, SIG_IGN);

        if (handle->opt.rfmon) {
                /*
                 * Monitor mode doesn't apply to Serial devices.
                 */
                close(handle->fd);
                return PCAP_ERROR_RFMON_NOTSUP;
        }

	/*
	 * "handle->fd" is a real file, so "select()" and "poll()"
	 * work on it.
	 */
	handle->selectable_fd = handle->fd;

	/* for plain binary access and text access we need to allocate the read
	 * buffer */
	handle->buffer = malloc(handle->bufsize);
	if (!handle->buffer) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "malloc: %s", pcap_strerror(errno));
		close(handle->fd);
		return PCAP_ERROR;
	}
        /* Set default timer for general serial capturing */
        timeout = SERIAL_PARSER_TIMEOUT;

        //Start a thread that listens to two serial ports and returns packets based on time
        //interval
        if(!serial_start_thread(handle)) return PCAP_ERROR;

        printf("Serial Activated.\n");
	return 0;
}

static int
serial_start_thread(pcap_t *handle)
{
    int status;
    handle->thread_run = 1;
    status = pthread_create(&(handle->thread), NULL, execute_parsing_thread_linux, (void *)handle);
    if(status) {
        printf("Error; status from pthread_create is %d\n", status);
        return PCAP_ERROR;
    }
    return 1;
}

static int
serial_read_linux(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{

    pcap_serial_packet_pointer *packet;
    struct pcap_pkthdr pkth;
    u_char *packet_data;

    //get from queue values for top two pointers (only remove first)
    packet = remove_from_queue(handle);
    if(packet == NULL)
        return 0;  //No packet in buffer

    //create the pcap packet header
    pkth.caplen = packet->length;
    pkth.len = packet->length;
    pkth.ts = packet->ts;

    packet_data = malloc(packet->length);
    /* send to callback */
    buffer_remove_data(handle, packet->position, packet_data, packet->length);
    callback(user, &pkth, packet_data);

    free(packet_data);
    free(packet);
    return 1;
}

static int
serial_inject_linux(pcap_t *handle, const void *buf, size_t size)
{
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not supported on "
		"Serial devices");
	return (-1);
}

static int
serial_stats_linux(pcap_t *handle, struct pcap_stat *stats)
{
	stats->ps_recv = handle->md.stat.ps_recv;
	stats->ps_drop = handle->md.stat.ps_drop;
	stats->ps_ifdrop = handle->md.stat.ps_ifdrop;
	return 0;
}

static int
serial_setfilter_linux(pcap_t *p, struct bpf_program *fp)
{
	return 0;
}

static int
serial_setdirection_linux(pcap_t *p, pcap_direction_t d)
{
	p->direction = d;
	return 0;
}

static int
serial_set_datalink(pcap_t *p, int dlt)
{
    printf("In serial_set_datalink %d %d\n", p->linktype, dlt);
    if(p->linktype == dlt) return 0;
    
    /* change the read_op and start/stop thread for serial */
    switch(dlt) {
        case DLT_SERIAL:
            printf("Changing datalink to serial\n");
            /* restart thread */
            timeout = SERIAL_PARSER_TIMEOUT;
            p->read_op = serial_read_linux;
            p->stats_op = serial_stats_linux;
            p->inject_op = serial_inject_linux;
            p->setfilter_op = serial_setfilter_linux;
            p->setdirection_op = serial_setdirection_linux;
            p->set_datalink_op = serial_set_datalink;
            if(!serial_start_thread(p)) return PCAP_ERROR;

            break;
        case DLT_DNP3:
            printf("Changing datalink to dnp\n");
            p->thread_run = 0;
            dnp_configure_datalink(p);
            break;
        case DLT_MODBUS:
            printf("Changing datalink to modbus\n");
            /* Calculate Modbus RTU timeout based on baud rate in milliseconds.
             * If > 19200 use fixed value of 1750us per spec otherwise
             * calculate 3.5 chars time */
            if(p->opt.baud > 19200) {
                timeout = 1.75;
            }
            else {
                /* (bits per character * second in milliseconds) / baud */
                timeout = (11 * 1000) / p->opt.baud;
            }
            /* clear buffers to restart with new timeout */
            buffer_clear(p);
            clear_queue(p);
            p->read_op = serial_read_linux;
            modbus_configure_datalink(p);
            break;
        case DLT_SSCP:
            printf("Changing datalink to sscp\n");
            p->thread_run = 0;
            sscp_configure_datalink(p);
            break;
    }
    p->linktype = dlt;
    return (0);
}

static int
serial_get_datalink(pcap_t *p)
{
    return p->linktype;
}

void *
execute_parsing_thread_linux(void* arg)
{
    pcap_t* handle;

    handle = (pcap_t*) arg;
    int numRead = 0;
    int current_packet_position = 0;
    handle->read_pointer = 0;
    handle->write_pointer = 0;
    handle->queue_start = 0;
    handle->queue_stop = 0;
    long timer = 0;

    u_char datachunk[255];
    struct timespec sleeptime, remtime={0};

    sleeptime.tv_sec = 0;
    sleeptime.tv_nsec = 50000000;
    while(handle->thread_run)
    {
        numRead = listen_serial_port(handle->fd, datachunk, sizeof(datachunk));

        if (numRead > 0 && numRead < buffer_size_free(handle)) {
            printf("Adding data %s\n", handle->opt.source);
            buffer_add_data(handle, datachunk, numRead);
            timer = get_time_millis();
        }
        
        if (get_time_millis() - timer >= timeout &&
                current_packet_position != handle->write_pointer) {
            pcap_serial_packet_pointer *packet = malloc(sizeof(pcap_serial_packet_pointer));
            packet->position = current_packet_position;
            packet->length = buffer_get_packet_len(handle, packet->position, handle->write_pointer - 1);
            gettimeofday(&packet->ts, NULL);
            append_to_queue(handle, packet);
            current_packet_position = handle->write_pointer;
            handle->md.stat.ps_recv++;
        }
        nanosleep(&sleeptime, &remtime);
    }
}

long
get_time_millis()
{
    struct timeval start;
    long mtime;

    gettimeofday(&start, NULL);
    mtime = ((start.tv_sec) * 1000 + start.tv_usec / 1000.0) + 0.5;

    return mtime;
}

int
listen_serial_port(int portDeviceID, unsigned char* listenbuf, int buf_size)
{

    int    res;
    struct timeval timeout;
    fd_set fdSet;

    FD_ZERO(&fdSet);
    FD_SET(portDeviceID, &fdSet);

    /* Initialize the timeout structure */
    timeout.tv_sec  = 0;
    timeout.tv_usec = 50000;

    /* Do the select */
    res = select(portDeviceID + 1, &fdSet, NULL, NULL, &timeout);

    if (res > 0) {
      if (FD_ISSET(portDeviceID, &fdSet)) {
        res = read(portDeviceID, listenbuf, buf_size);
        if (res > 0) return res;
      }
    }

    return 0;
}


/*Functions dealing with ring buffer for use by the time based
/packetizing thread.*/
/*buffer_get_space_size is not inclusive of end position*/
int 
buffer_get_space_size(pcap_t* handle, int start, int end)
{
    if(end > start) return end - start;
    else if(start == end) return 0;
    else return  handle->bufsize - start + end;
}

int
buffer_size_free(pcap_t* handle)
{
    if(handle->write_pointer == handle->read_pointer) return handle->bufsize;
   return buffer_get_space_size(handle, handle->write_pointer, handle->read_pointer);
}

int
buffer_get_data_size(pcap_t* handle)
{
    return buffer_get_space_size(handle, handle->read_pointer, handle->write_pointer);
}

int
buffer_get_packet_len(pcap_t* handle, int start, int end)
{
    if(start <= end) return end - start + 1;
    else {
        return handle->bufsize - ((start - 1) - end);
    }
}

void
buffer_add_data(pcap_t* handle, unsigned char *data, int size) {
    int i;

    // loop through the data and add it to the ring buffer
    for (i = 0; i < size; i++) {
        // if at the end of ring buffer wrap to beginning
        if (handle->write_pointer == handle->bufsize) handle->write_pointer = 0;
        // put the data in the ring buffer
        handle->buffer[handle->write_pointer] = data[i];
        // increment write ptr to next index
        handle->write_pointer++;
    }
    return;
}

void
buffer_get_data(pcap_t* handle, int pos, unsigned char * data, int size)
{
    int i;

    for(i = 0; i < size; i++)
    {
        data[i] = handle->buffer[(pos + i) % handle->bufsize];
    }
}

void
buffer_remove_data(pcap_t* handle, int pos, unsigned char * data, int size)
{

    buffer_get_data(handle, pos, data, size);
    buffer_move_read_pointer(handle, pos, size);
}

void
buffer_move_read_pointer(pcap_t* handle, int pos, int size) {
    handle->read_pointer = (pos + size) % handle->bufsize;
}

u_char
buffer_get_byte(pcap_t* handle, int pos, int offset)
{
    return handle->buffer[(pos + offset) % handle->bufsize];
}

void
buffer_clear(pcap_t* handle) {
    handle->read_pointer = handle->write_pointer = 0;
}

//Functions dealing with packet index queue for use by the time based
//packetizing thread.
int
append_to_queue(pcap_t* handle, pcap_serial_packet_pointer *add_item) {
    if(handle->queue_stop+1==handle->queue_start ||
            (handle->queue_stop+1==QUEUE_MAX && !handle->queue_start)) {
        return -1;
    }
    handle->queue[handle->queue_stop] = add_item;
    handle->queue_stop++;
    if(handle->queue_stop==QUEUE_MAX) handle->queue_stop = 0;
}

pcap_serial_packet_pointer *
remove_from_queue(pcap_t* handle) {
    if(handle->queue_start==QUEUE_MAX) handle->queue_start = 0;
    if(handle->queue_start == handle->queue_stop) return NULL;
    handle->queue_start++;

    return handle->queue[handle->queue_start-1];
}

pcap_serial_packet_pointer *
peek_on_queue(pcap_t* handle) {
    return handle->queue[handle->queue_start];
}

void
clear_queue(pcap_t* handle) {
    pcap_serial_packet_pointer *packet;
    while((packet = remove_from_queue(handle)) != NULL) {
        free(packet);
    }
}
