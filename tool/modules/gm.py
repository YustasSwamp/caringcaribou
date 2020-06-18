from __future__ import print_function
from lib.common import parse_int_dec_or_hex, int_list_to_ascii, int_from_byte_list
import modules.uds as uds
from lib.iso14229_1 import ServiceID
from sys import stdout, version_info
from datetime import datetime, timedelta
import argparse

# Handle large ranges efficiently in both python 2 and 3
if version_info[0] == 2:
    range = xrange

# Based on https://github.com/YustasSwamp/gm-seed-key/
def algo_96(seed):
    data = seed - 0x9083
    data = ((data >> 8) & 0xff) | ((data << 8) & 0xff00)
    data = (data + 0xa076) & 0xffff
    data = (data >> 5 | data << (11)) & 0xffff
    data = (data - 0x5b68) & 0xffff
    return data

def algo_92(seed):
    raise Exception("Implement me")

def algo_87(seed):
    raise Exception("Implement me")

# Based on http://download.efilive.com/Documentation/OS%20Compatibility%20Guide.pdf
# and https://forum.hptuners.com/showthread.php?39267-beta-update-tread&p=296415&viewfull=1#post296415
OSID_TO_ECM = {
    12610011: "e37",
    12617248: "e37",
    12618029: "e37",
    12618032: "e37",
    12628829: "e37",
    12628830: "e37",
    12628960: "e37",
    12628961: "e37",
    12630187: "e37",
    12634915: "e37",
    12635399: "e37",
    12635813: "e37",
    12635814: "e37",
    12635865: "e37",
    12639473: "e37",
    12639670: "e37",
    12639673: "e37",
    12640965: "e37",
    12647468: "e37",
    12653247: "e37",
    12653292: "e37",
    12653628: "e37",
    12653771: "e37"
}

ECM_SPECS = {
    "e37": {
        "key_algo": algo_96,
        "mem_addr": 0,
        "mem_size": 0x200000,
        "mem_addr_bytes": 4,
    },
    "e38": {
        "key_algo": algo_92,
        "mem_addr": 0,
        "mem_size": 0x200000,
        "mem_addr_bytes": 4,
    },
    "e67": {
        "key_algo": algo_89,
        "mem_addr": 0,
        "mem_size": 0x200000,
        "mem_addr_bytes": 4,
    }
}

thread = None
thread_stop = False

def read_ecm(args):
    """
    Read ECM ROM.

    :param args: A namespace containing output filename, start address and size
    """
    filename = args.filename
    addr = args.addr
    size = args.size

    # Use hardcodded 0x7e0 ECM Arb ID
    send_arb_id = 0x7e0

    #
    # 1. Ping ECM by discovering response Arb ID
    #
    print("Probe ECM by ID 0x{0:03x}:".format(send_arb_id))
    arb_id_pairs = uds.uds_discovery(send_arb_id, send_arb_id,
                                     print_results=False)
    if len(arb_id_pairs) != 1:
        print("  ECM is not found")
        return
    (a, rcv_arb_id) = arb_id_pairs[0]
    print("  ECM is detected... response ID 0x{0:03x}".format(rcv_arb_id))

    #
    # 2. Scan for needed services availability
    #
    print("Probe ECM services:")
    needed_services = [
        0x1a, # GMLAN_READ_DIAGNOSTIC_ID
        ServiceID.READ_MEMORY_BY_ADDRESS,
        ServiceID.SECURITY_ACCESS,
        ServiceID.TESTER_PRESENT
    ]
    found_services = uds.service_discovery(send_arb_id, rcv_arb_id,
                                           min_id=min(needed_services),
                                           max_id=max(needed_services),
                                           print_results=False)
    found_services = found_services and needed_services
    missing_services = set(needed_services) - set(found_services)
    if len(missing_services) != 0:
        print("  Missing services: ", end="")
        print(", ".join('{}'.format(uds.UDS_SERVICE_NAMES[s]) for s in missing_services))
        return
    print("  All needed services are present")

    #
    # 3. Read ECM info
    #
    print("Read ECM info:")
    vin_did = uds.service_1a(send_arb_id, rcv_arb_id, 0x90, 0x90)
    if len(vin_did) == 1:
        vin = int_list_to_ascii(vin_did[0x90])
    else:
        vin = "<not found>"
    print("  VIN: {}".format(vin))

    os_did = uds.service_1a(send_arb_id, rcv_arb_id, 0xc1, 0xc1)
    if len(os_did) != 1:
        print("  OS ID: <not found>")
        return
    else:
        osid = int_from_byte_list(os_did[0xc1])
    print("  OS ID: {}".format(osid))

    ecm_type = OSID_TO_ECM.get(osid)
    if not ecm_type:
        print("Not supported OS ID!")
        return
    print("  ECM type: {}".format(ecm_type))
    ecm_spec = ECM_SPECS[ecm_type]

    #
    # 4. Input addr/size sanity check
    #
    ecm_mem_addr = ecm_spec['mem_addr']
    ecm_mem_size = ecm_spec['mem_size']
    if not addr:
        addr = ecm_mem_addr
    if not size:
        size = ecm_mem_size - addr
    if addr < ecm_mem_addr or addr >= ecm_mem_addr + ecm_mem_size:
        print("Incorrect 'addr' for the ECM, valid range: [0x{0:x};0x{1:x})".format(ecm_mem_addr, ecm_mem_addr + ecm_mem_size))
        return
    if size <= 0 or size + addr > ecm_mem_addr + ecm_mem_size:
        print("Incorrect 'addr+size' address out of ECM memory, valid range: [0x{0:x};0x{1:x})".format(ecm_mem_addr, ecm_mem_addr + ecm_mem_size))
        return

    #
    # 5. Unlock the ECM
    #
    print("Unlock ECM:")
    (seed, err) = uds.service_27(send_arb_id, rcv_arb_id, None)
    if err:
        print("  Unable to get seed: {}".format(err))
        return
    print("  Got seed: 0x{0:04x}".format(seed))

    key = ecm_spec['key_algo'](seed)
    print("  Use key:  0x{0:04x}".format(key))
    (_, err) = uds.service_27(send_arb_id, rcv_arb_id, key)
    if err:
        print("  Error: {}".format(err))
        return
    print("  Unlocked!")

    #
    # 6. Read memory
    #
    print("Read ECU memory:")
    ret = uds.read_memory(send_arb_id, rcv_arb_id, filename, addr, size,
                          ecm_spec['mem_addr_bytes'], tester_present=True)
    if ret:
        print(" "*40 + "\r  Completed!")


def __parse_args(args):
    """Parser for module arguments"""
    parser = argparse.ArgumentParser(
                prog="cc.py gm",
                formatter_class=argparse.RawDescriptionHelpFormatter,
                description="GM module for "
                "CaringCaribou",
                epilog="""Example usage:"
  cc.py gm read_ecm my_ecm.bin
  cc.py gm read_ecm my_ecm.bin -addr 0xa000 -size 0x4000""")
    subparsers = parser.add_subparsers(dest="module_function")
    subparsers.required = True

    # Parser for read_ecm
    parser_read_ecm = subparsers.add_parser("read_ecm")
    parser_read_ecm.add_argument("filename", help="filename to save to")
    parser_read_ecm.add_argument("-addr", type=parse_int_dec_or_hex, default=None, help="ROM address to start reading from")
    parser_read_ecm.add_argument("-size", type=parse_int_dec_or_hex, default=None, help="Number of bytes to read")
    parser_read_ecm.set_defaults(func=read_ecm)

    args = parser.parse_args(args)
    return args


def module_main(arg_list):
    """Module main wrapper"""
    try:
        args = __parse_args(arg_list)
        t1 = datetime.now()
        args.func(args)
        t2 = datetime.now()
        print("\nElapsed time (hh:mm:ss.ms): {}".format(t2 - t1))
    except KeyboardInterrupt:
        print("\nTerminated by user")
