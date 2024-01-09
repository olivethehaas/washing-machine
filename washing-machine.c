/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 *  gpio 02 --> data
 *  gpio 03 --> clock
 *  gpio 04 --> strobe
 * 
 * Detect a special pattern at the end of washing cycle
 * 
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

#define PIO_DATA_PIN 2


int main() {
    stdio_init_all();
    char pattern[] = {0x03, 0x40, 0xC0, 0x8E, 0x03, 0x40};
    int patternIndex = 0;
    int patternSize = sizeof(pattern)/sizeof(pattern[0]);
    int incomingByte = 0;
    printf("Machine démarrage\n");
    PIO pio = pio0;
    uint sm = 0;
    uint offset = pio_add_program(pio, &wm_program);
    wm_program_init(pio, sm, offset,PIO_DATA_PIN);
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
    return 0;
    }
