/* run 'python3 build.py' to generate the ffi bindings before running jtag-gpio.py */
#include "gpio-ffi.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

//#define BCM2708_PERI_BASE 0x3F000000 // tested on Rpi3
#define GPIO_BASE (base + 0x200000)
#define GPIO_LENGTH 4096

typedef unsigned int uint32_t;

volatile uint32_t* pi_mmio_gpio = NULL;

unsigned int pi_mmio_init(unsigned int base) {
  if (pi_mmio_gpio == NULL) {
    int fd;

    // On older kernels user readable /dev/gpiomem might not exists.
    // Falls back to root-only /dev/mem.
    if( access( "/dev/gpiomem", F_OK ) != -1 ) {
      fd = open("/dev/gpiomem", O_RDWR | O_SYNC);
    } else {
      fd = open("/dev/mem", O_RDWR | O_SYNC);
    }
    if (fd == -1) {
      // Error opening /dev/gpiomem.
      return 0;
    }
    // Map GPIO memory to location in process space.
    pi_mmio_gpio = (uint32_t*)mmap(NULL, GPIO_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED, fd, GPIO_BASE);
    close(fd);
    if (pi_mmio_gpio == MAP_FAILED) {
      // Don't save the result if the memory mapping failed.
      pi_mmio_gpio = NULL;
      return 0;
    }
  }
  return (unsigned int) pi_mmio_gpio;
}

#define GPIO_SET *((volatile unsigned int *)(gpio+7*4))  // sets   bits which are 1 ignores bits which are 0
#define GPIO_CLR *((volatile unsigned int *)(gpio+10*4)) // clears bits which are 1 ignores bits which are 0
#define GPIO_LVL *((volatile unsigned int *)(gpio+13*4))

#define TCK_PIN 4
#define TMS_PIN 17
#define TDI_PIN 27
#define TDO_PIN 22

int jtag_pins(int tdi, int tms, unsigned int gpio) {

  GPIO_CLR = 1 << TCK_PIN;

  if(tdi)
    GPIO_SET = 1 << TDI_PIN;
  else
    GPIO_CLR = 1 << TDI_PIN;

  if(tms)
    GPIO_SET = 1 << TMS_PIN;
  else
    GPIO_CLR = 1 << TMS_PIN;

  GPIO_SET = 1 << TCK_PIN;

  return (GPIO_LVL & (1 << TDO_PIN)) ? 1 : 0;
}

int jtag_prog(char *bitstream, unsigned int gpio) {

  GPIO_CLR = 1 << TMS_PIN; // TMS is known to be zero for this operation
  int i = 0;
  while(bitstream[i] != '\0') {
    GPIO_CLR = 1 << TCK_PIN;

    if(bitstream[i] == '1')
      GPIO_SET = 1 << TDI_PIN;
    else
      GPIO_CLR = 1 << TDI_PIN;

    GPIO_SET = 1 << TCK_PIN;

    i++;
  }

  return 0; // we ignore TDO for speed
}

void jtag_prog_rbk(char *bitstream, unsigned int gpio, char *readback) {

  GPIO_CLR = 1 << TMS_PIN; // TMS is known to be zero for this operation
  int i = 0;
  GPIO_CLR = 1 << TCK_PIN;
  while(bitstream[i] != '\0') {
    if(bitstream[i] == '1')
      GPIO_SET = 1 << TDI_PIN;
    else
      GPIO_CLR = 1 << TDI_PIN;

    GPIO_SET = 1 << TCK_PIN; // clock needs stretching on the rpi4
    GPIO_SET = 1 << TCK_PIN;
    GPIO_SET = 1 << TCK_PIN;
    GPIO_SET = 1 << TCK_PIN;
    
    GPIO_CLR = 1 << TCK_PIN; // meet hold time
    GPIO_CLR = 1 << TCK_PIN;
    GPIO_CLR = 1 << TCK_PIN;
    GPIO_CLR = 1 << TCK_PIN;

    if (GPIO_LVL & (1 << TDO_PIN)) {
       readback[i] = '1';
    } else {
       readback[i] = '0';
    }

    i++;
  }
}
