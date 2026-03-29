#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "hal_time.h"
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

void listener(GooseSubscriber sub, void* param) {

    uint64_t recvTime = Hal_getTimeInMs();
    uint64_t sentTime = GooseSubscriber_getTimestamp(sub);

    uint64_t latency = recvTime - sentTime;

    printf("Received GOOSE!\n");
    printf("stNum=%u sqNum=%u\n",
        GooseSubscriber_getStNum(sub),
        GooseSubscriber_getSqNum(sub));

    printf("Latency = %" PRIu64 " ms\n\n", latency);
}

int main() {

    GooseReceiver receiver = GooseReceiver_create();

    GooseSubscriber sub = GooseSubscriber_create(
        "simpleIO/LLN0$GO$gcb1", NULL);

    GooseSubscriber_setListener(sub, listener, NULL);

    GooseReceiver_addSubscriber(receiver, sub);

    // CHANGE interface name if needed
    GooseReceiver_setInterfaceId(receiver, "enp0s3");

    printf("Subscriber started...\n");

    GooseReceiver_start(receiver);

    while (1) {
        sleep(1);
    }

    return 0;
}
