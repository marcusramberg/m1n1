# SPDX-License-Identifier: MIT

import usb.core
import usb.util


class UsbCdcTransport:
    """Minimal direct-USB transport for DWC3 targets that need full OUT TRBs."""

    out_transfer_size = 16 * 1024
    raw_usb = True

    def __init__(self, vendor=0x1209, product=0x316D):
        self.vendor = vendor
        self.product = product
        self.timeout = 3
        self.baudrate = 115200
        self.dev = None
        self.detached = []
        self.rx_buffer = bytearray()
        self.open()

    def open(self):
        if self.dev is not None:
            return

        dev = usb.core.find(idVendor=self.vendor, idProduct=self.product)
        if dev is None:
            raise IOError("m1n1 USB device 1209:316d not found")

        self.detached = []
        for interface in (0, 1):
            if dev.is_kernel_driver_active(interface):
                dev.detach_kernel_driver(interface)
                self.detached.append(interface)

        usb.util.claim_interface(dev, 0)
        usb.util.claim_interface(dev, 1)
        dev.ctrl_transfer(0x21, 0x22, 1, 0, None, timeout=2000)
        self.dev = dev

    def close(self):
        if self.dev is None:
            return

        dev = self.dev
        self.dev = None
        try:
            dev.ctrl_transfer(0x21, 0x22, 0, 0, None, timeout=1000)
        except usb.core.USBError:
            pass
        for interface in (1, 0):
            try:
                usb.util.release_interface(dev, interface)
            except usb.core.USBError:
                pass
        for interface in self.detached:
            try:
                dev.attach_kernel_driver(interface)
            except usb.core.USBError:
                pass
        usb.util.dispose_resources(dev)

    def write(self, data):
        if self.dev is None:
            raise IOError("USB transport is closed")
        timeout = max(1, int((self.timeout or 3) * 1000))
        return self.dev.write(0x02, data, timeout=timeout)

    def read(self, size):
        if self.dev is None:
            return b""
        if self.rx_buffer:
            data = bytes(self.rx_buffer[:size])
            del self.rx_buffer[:size]
            return data
        timeout = max(1, int((self.timeout or 0.001) * 1000))
        try:
            self.rx_buffer.extend(self.dev.read(0x82, 16384, timeout=timeout))
        except usb.core.USBTimeoutError:
            return b""
        data = bytes(self.rx_buffer[:size])
        del self.rx_buffer[:size]
        return data

    def flushOutput(self):
        pass

    def flushInput(self):
        if self.dev is None:
            return
        self.rx_buffer.clear()
        while True:
            try:
                self.dev.read(0x82, 16384, timeout=1)
            except usb.core.USBTimeoutError:
                return

    reset_input_buffer = flushInput
    reset_output_buffer = flushOutput
