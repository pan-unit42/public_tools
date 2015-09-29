__author__ = 'wartortell'

import idaapi
import idautils
import idc

bad_jump_count = 0
for head in idautils.Heads():

    for xref in idautils.XrefsFrom(head, 0):
        # Find direct jump instructions
        if xref.type == 19:

            next_head = head + idaapi.get_item_size(head)

            # Make sure we aren't handling jump tables
            if idc.Byte(next_head) == 0xFF:
                continue

            # Now check that the next instruction is a direct jump of length 0
            for xref2 in idautils.XrefsFrom(next_head, 0):
                third_head = next_head + idaapi.get_item_size(next_head)
                if (xref2.type == 19) and (xref2.to == third_head):

                    db = head + idaapi.get_item_size(head)

                    print "Bad jump: %8X -> %8X, changing to direct JMP" % (head, xref.to)

                    # Change head to a direct jump
                    if idc.Byte(head) == 0x0F:
                        idaapi.patch_byte(head, 0x90)
                        idaapi.patch_byte(head+1, 0xE9)
                    else:
                        idaapi.patch_byte(head, 0xEB)

                    # Undefine and redefine code borders
                    idc.MakeUnknown(db, xref.to - db + 0x10, idaapi.DOUNK_SIMPLE)
                    idc.MakeCode(xref.to)

                    # Convert the bad code into bytes
                    i = db
                    while i < xref.to:
                        if (i+4) < xref.to:
                            idc.MakeDword(i)
                            i += 4
                        else:
                            idc.MakeByte(i)
                            i += 1

                    # Analyze the area to fix xrefs
                    idaapi.analyze_area(head-0x40, head+0x40)
                    idaapi.analyze_area(xref.to-0x40, xref.to+0x40)

                    bad_jump_count += 1

print "Fixed %d anti-disassembly instructions." % bad_jump_count

# Make sure that all calls go to functions
for head in idautils.Heads():
    if idc.Byte(head) == 0xE8:
        for xref in idautils.XrefsFrom(head, 0):
            # Find direct call targets
            if not (xref.type == 21):
                idc.MakeFunction(xref.to)

