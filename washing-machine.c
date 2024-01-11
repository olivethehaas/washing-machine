/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *  washing machine type LG F74890WH
 *  sniff display driver IK2102DW
 *  https://monitor.espec.ws/files/ik2102_293.pdf
 * 
 *  gpio 02 --> data
 *  gpio 03 --> clock
 *  gpio 04 --> strobe
 * 
 * Detect a special pattern at the end of washing cycle
 * Send Notification to NTFY.SH 
 * 
 * 
 * 
 * 
 */

#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/pio.h"
#include "wm.pio.h"
#include "pico/cyw43_arch.h"
#include "lwip/altcp.h"
#include "lwip/dns.h"


#define PIO_DATA_PIN 2
#define BUF_SIZE 2048

char ssid[] = "Livebox-ACF6";
char pass[] = "49iQHvXum9SAarZkCE";
uint32_t country = CYW43_COUNTRY_FRANCE;
uint32_t auth = CYW43_AUTH_WPA2_MIXED_PSK;
char myBuff[BUF_SIZE];
char header[] = "POST /RP2040-Machinealaver HTTP/1.1\r\n" \
                "HOST: ntfy.sh\r\n" \
                "Title: Machine Terminée\r\n" \
                "Message: Faut vider dans 5 min !\r\n" \
                "Priority: high\r\n" \
                "Tags: tada, partying_face\r\n" \
                "\n";

int setup(uint32_t country, const char *ssid, const char *pass,uint32_t auth, const char *hostname, ip_addr_t *ip, ip_addr_t *mask, ip_addr_t *gw)
{

    if (cyw43_arch_init_with_country(country)) /* connection succesfull 0 */
    {
        return 1; 
    }

    cyw43_arch_enable_sta_mode();
    if (hostname != NULL)
    {
        netif_set_hostname(netif_default, hostname);
    }
    if (cyw43_arch_wifi_connect_async(ssid, pass, auth))
    {
        return 2;
    }
    int flashrate = 1000;
    int status = CYW43_LINK_UP + 1;
    while (status >= 0 && status != CYW43_LINK_UP)
    {
        int new_status = cyw43_tcpip_link_status(&cyw43_state,
                                                 CYW43_ITF_STA);
        if (new_status != status)
        {
            status = new_status;
            flashrate = flashrate / (status + 1);
            printf("connect status: %d %d\n", status, flashrate);
        }
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
        sleep_ms(flashrate);
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
        sleep_ms(flashrate);
    }
    if (status < 0)
    {
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
    }
    else
    {
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
        if (ip != NULL)
        {
            netif_set_ipaddr(netif_default, ip);
        }
        if (mask != NULL)
        {
            netif_set_netmask(netif_default, mask);
        }
        if (gw != NULL)
        {
            netif_set_gw(netif_default, gw);
        }

        printf("IP: %s\n",
               ip4addr_ntoa(netif_ip_addr4(netif_default)));
        printf("Mask: %s\n",
               ip4addr_ntoa(netif_ip_netmask4(netif_default)));
        printf("Gateway: %s\n",
               ip4addr_ntoa(netif_ip_gw4(netif_default)));
        printf("Host Name: %s\n",
               netif_get_hostname(netif_default));
    }
    return status;
}

err_t recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err)
{

    if (p != NULL)
    {
        printf("recv total %d  this buffer %d next %d err %d\n", p->tot_len, p->len, p->next, err);
                if ((p->tot_len) > 2)
        {
        pbuf_copy_partial(p, myBuff, p->tot_len, 0);
        myBuff[p->tot_len] = 0;        
        printf("Buffer= %s\n", myBuff);
        altcp_recved(pcb, p->tot_len);
        }
        pbuf_free(p);
    }    else
    {
        printf("Connection Closed");
        altcp_close(pcb);
    }
    return ERR_OK;
}

err_t sent(void *arg, struct altcp_pcb *pcb, u16_t len)
{
    printf("data sent %d\n", len);
}

void err(void *arg, err_t err)
{
    if (err != ERR_ABRT)
    {
        printf("client_err %d\n", err);
    }
}

err_t altcp_client_connected(void *arg, struct altcp_pcb *pcb, err_t err)
{
    err = altcp_write(pcb, header, strlen(header), 0);
    err = altcp_output(pcb);

    return ERR_OK;
}

err_t poll(void *arg, struct altcp_pcb *pcb){
        printf("Connection Closed");
        altcp_close(pcb);
}

void dns_found(const char *name, const ip_addr_t *ip, void *arg)
{
    ip_addr_t *ipResult = (ip_addr_t *)arg;
    if (ip)
    {
        ip4_addr_copy(*ipResult, *ip);
    }
    else
    {
        ip4_addr_set_loopback(ipResult);
    }
    return;
}

err_t getIP(char *URL, ip_addr_t *ipResult)
{
    cyw43_arch_lwip_begin();
    err_t err = dns_gethostbyname(URL, ipResult, dns_found, ipResult);
    cyw43_arch_lwip_end();
    return err;
}


int main()
 {
    stdio_init_all();
    char pattern[] = {0x03, 0x40, 0xC0, 0x8E, 0x03, 0x40};
    int patternIndex = 0;
    int patternSize = sizeof(pattern)/sizeof(pattern[0]);
    int incomingByte = 0;
    printf("Machine démarrage\n");
    sleep_ms(300000);
    printf("Sniff Sniff\n");
    PIO pio = pio0;
    uint sm = 0;
    uint offset = pio_add_program(pio, &wm_program);
    wm_program_init(pio, sm, offset,PIO_DATA_PIN); // start PIO state machine

    while(true){
        incomingByte = wm_program_getc(pio, sm);
        if(pattern[patternIndex] == incomingByte) 
        {
            if (patternIndex == patternSize-1)
            {
                break;
            }
            patternIndex ++;
        }
        else 
        {
            patternIndex = 0;
        }
    }

    printf("Machine terminée\n");

    setup(country, ssid, pass, auth,NULL,NULL,NULL,NULL);
    // application layered TCP
    struct altcp_pcb *pcb = altcp_new(NULL);
    altcp_recv(pcb, recv);
    altcp_sent(pcb, sent);
    altcp_err(pcb, err);
    altcp_poll(pcb, poll,10);

    ip_addr_t ip;
    ip4_addr_set_zero(&ip);
    getIP("ntfy.sh", &ip);
    while (!ip_addr_get_ip4_u32(&ip))
    {
        sleep_ms(100);
    };
    if (ip4_addr_isloopback(&ip))
    {
        printf("address not found");
    }

    cyw43_arch_lwip_begin();
    err_t err = altcp_connect(pcb, &ip, 80, altcp_client_connected);
    cyw43_arch_lwip_end();
    while (true)
    {
        sleep_ms(500);
    }
}
