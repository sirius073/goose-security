#include "goose_publisher.h"
#include "linked_list.h"
#include "mms_value.h"
#include "hal_thread.h"
#include <stdio.h>
#include <unistd.h>

int main() {

    CommParameters params;

    uint8_t dstMac[] = {0x01,0x0c,0xcd,0x01,0x00,0x01}; // GOOSE multicast
    params.dstAddress = dstMac;
    params.vlanId = 0;
    params.vlanPriority = 4;
    params.appId = 1000;

    // CHANGE interface name if needed (check with: ip a)
    GoosePublisher pub = GoosePublisher_create(&params, "enp0s3");

    GoosePublisher_setGoCbRef(pub, "simpleIO/LLN0$GO$gcb1");
    GoosePublisher_setDataSetRef(pub, "simpleIO/LLN0$dataset1");
    GoosePublisher_setConfRev(pub, 1);

    LinkedList dataSet = LinkedList_create();

    MmsValue* val = MmsValue_newBoolean(true);
    LinkedList_add(dataSet, val);

    printf("Publisher started...\n");

    while (1) {

        GoosePublisher_increaseStNum(pub);  // updates timestamp

        GoosePublisher_publish(pub, dataSet);

        printf("GOOSE message sent\n");

        sleep(1);
    }

    return 0;
}
