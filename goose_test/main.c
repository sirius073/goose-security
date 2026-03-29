#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h> // For high-resolution microsecond timing

#include "hal_thread.h"
#include "goose_publisher.h"
#include "goose_receiver.h"
#include "goose_subscriber.h"

// -------------------------------------------------------------
// 1. THE SUBSCRIBER LISTENER CALLBACK
// -------------------------------------------------------------
void gooseListener(GooseSubscriber subscriber, void* parameter) {
    // Grab the current time the exact moment the message arrives
    struct timeval tv_rx;
    gettimeofday(&tv_rx, NULL);

    MmsValue* values = GooseSubscriber_getDataSetValues(subscriber);
    if (values == NULL) return;

    // Extract the Tx timestamp sent by the publisher
    MmsValue* sec_val = MmsValue_getElement(values, 0);
    MmsValue* usec_val = MmsValue_getElement(values, 1);

    if (sec_val && usec_val) {
        int32_t tx_sec = MmsValue_toInt32(sec_val);
        int32_t tx_usec = MmsValue_toInt32(usec_val);

        // Calculate latency in microseconds
        long delta_usec = (tv_rx.tv_sec - tx_sec) * 1000000L + (tv_rx.tv_usec - tx_usec);
        
        printf(" -> Subscriber caught GOOSE! Latency: %ld microseconds\n", delta_usec);
    }
}

int main(int argc, char** argv) {
    // We use the loopback interface so we don't need two separate machines
    char* interface = "lo"; 
    if (argc > 1) interface = argv[1];

    printf("Starting GOOSE Publisher & Subscriber on interface '%s'...\n\n", interface);

    // -------------------------------------------------------------
    // 2. SETUP RECEIVER & SUBSCRIBER
    // -------------------------------------------------------------
    GooseReceiver receiver = GooseReceiver_create();
    GooseReceiver_setInterfaceId(receiver, interface);

    GooseSubscriber subscriber = GooseSubscriber_create("myGooseCbRef", NULL);
    GooseSubscriber_setAppId(subscriber, 1000);
    GooseSubscriber_setListener(subscriber, gooseListener, NULL);

    GooseReceiver_addSubscriber(receiver, subscriber);
    GooseReceiver_start(receiver);

    // -------------------------------------------------------------
    // 3. SETUP PUBLISHER
    // -------------------------------------------------------------
    CommParameters commParams;
    commParams.appId = 1000;
    commParams.vlanId = 0;
    commParams.vlanPriority = 4;
    uint8_t dstMac[6] = {0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01}; // Standard GOOSE Multicast
    memcpy(commParams.dstAddress, dstMac, 6);

    GoosePublisher publisher = GoosePublisher_create(&commParams, interface);
    if (!publisher) {
        printf("ERROR: Failed to create GOOSE publisher. Did you run with 'sudo'?\n");
        return 1;
    }

    GoosePublisher_setGoCbRef(publisher, "myGooseCbRef");
    GoosePublisher_setConfRev(publisher, 1);
    GoosePublisher_setDataSetRef(publisher, "myDataset");

    // Create the dataset (holds seconds and microseconds)
    LinkedList dataSet = LinkedList_create();
    MmsValue* sec_mms = MmsValue_newIntegerFromInt32(0);
    MmsValue* usec_mms = MmsValue_newIntegerFromInt32(0);
    LinkedList_add(dataSet, sec_mms);
    LinkedList_add(dataSet, usec_mms);

    // -------------------------------------------------------------
    // 4. PUBLISH LOOP
    // -------------------------------------------------------------
    for (int i = 0; i < 5; i++) {
        struct timeval tv_tx;
        gettimeofday(&tv_tx, NULL);

        // Update dataset with current time before packing the payload
        MmsValue_setInt32(sec_mms, (int32_t)tv_tx.tv_sec);
        MmsValue_setInt32(usec_mms, (int32_t)tv_tx.tv_usec);

        GoosePublisher_increaseStNum(publisher); 
        GoosePublisher_publish(publisher, dataSet);
        
        printf("Published GOOSE message #%d...\n", i+1);
        
        Thread_sleep(1000); // Wait 1 second before sending the next
    }

    // -------------------------------------------------------------
    // 5. CLEANUP
    // -------------------------------------------------------------
    GooseReceiver_stop(receiver);
    GooseReceiver_destroy(receiver);
    GoosePublisher_destroy(publisher);
    LinkedList_destroy(dataSet);

    printf("\nFinished simulation.\n");
    return 0;
}
