/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.sdnfv.AutoReachabilityDetect;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowEntry.FlowEntryState;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.Host;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onlab.packet.Ethernet;
import org.onlab.packet.EthType.EtherType;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IPv4;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMPEcho;
import java.nio.ByteBuffer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CountDownLatch;
import java.lang.System;
import java.io.*;

/**
 * Automatically detect reachability between hosts.
 */
@Component(immediate = true)
@Service
public class AppComponent implements AppComponentService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    private ApplicationId appId;
    private PktProcessor processor = new PktProcessor();

    private Timer timer = new Timer();
    private TimeoutHandler handler;

    private static short ident = 0;
    private static short seqNum = 0;

    private Ip4Address srcIP;
    private Ip4Address dstIP;
    private static final int DEFAULT_MAX_COUNT = 3;
    private static final int DEFAULT_TIMEOUT_SECOND = 3;
    private int count;
    private int sent;
    private int timeout;

    private CountDownLatch latch;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nctu.sdnfv.AutoReachabilityDetect");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    public void ping(String srcIP, String dstIP, int count, int timeout) {
        this.srcIP = Ip4Address.valueOf(srcIP);
        this.dstIP = Ip4Address.valueOf(dstIP);
        this.timeout = timeout == 0 ? DEFAULT_TIMEOUT_SECOND : timeout;
        this.count = count == 0 ? DEFAULT_MAX_COUNT : count;
        sent = 0;
        latch = new CountDownLatch(this.count);

        log.info("+++++++++++++++++++++++++++++++++++++++++++++++++");
        log.info(srcIP.toString() + " PING " + dstIP.toString());

        installRule(this.dstIP, this.srcIP);
        installRule(this.srcIP, this.dstIP);
        log.info("installing rules...");
        waitRulesInstallation();
        internalPing();
        try {
            latch.await();
        } catch (InterruptedException e) {};
        flowRuleService.removeFlowRulesById(appId);
    }

    private void internalPing() {
        if (++sent > count) {
            log.info("+++++++++++++++++++++++++++++++++++++++++++++++++");
            return;
        }
        handler = new TimeoutHandler();
        timer.schedule(handler, timeout * 1000);
        log.info("-------------------------------------------------");
        log.info("Send ECHO to " + dstIP.toString() + ", icmp_seq = " + (seqNum + 1));
        sendIcmpEchoPkt(srcIP, dstIP);
    }

    private void installRule(Ip4Address src, Ip4Address dst) {
        Host srcHost = hostService.getHostsByIp(srcIP).iterator().next();
        DeviceId deviceId = srcHost.location().deviceId();

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_ICMP)
                .matchIPSrc(Ip4Prefix.valueOf(src, Ip4Prefix.MAX_MASK_LENGTH))
                .matchIPDst(Ip4Prefix.valueOf(dst, Ip4Prefix.MAX_MASK_LENGTH))
                .matchIcmpType(ICMP.TYPE_ECHO_REPLY)
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.CONTROLLER)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(PacketPriority.MAX.priorityValue())
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .add();
        
        flowObjectiveService.forward(deviceId, forwardingObjective);
    }

    private void waitRulesInstallation() {
        Host srcHost = hostService.getHostsByIp(srcIP).iterator().next();
        DeviceId deviceId = srcHost.location().deviceId();
        while (flowRuleService.getFlowEntriesByState(
                    deviceId,
                    FlowEntry.FlowEntryState.PENDING_ADD).iterator().hasNext());
    }

    private class PktProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Pkt = (IPv4)ethPkt.getPayload();
                Ip4Address from = Ip4Address.valueOf(ipv4Pkt.getSourceAddress());
                Ip4Address to = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());
                ICMP icmpPkt = (ICMP)ipv4Pkt.getPayload();
                int icmpSeq = ((ICMPEcho)icmpPkt.getPayload()).getSequenceNum();

                if (ipv4Pkt.getProtocol() == IPv4.PROTOCOL_ICMP &&
                        icmpPkt.getIcmpType() == ICMP.TYPE_ECHO_REPLY &&
                        icmpSeq == seqNum) {
                    if (from.equals(dstIP) && to.equals(srcIP)) {
                        log.info("Recv REPLY from " + dstIP.toString() + ", icmp_seq = " + icmpSeq);
                        log.info("Send ECHO to " + srcIP.toString() + ", icmp_seq = " + (seqNum + 1));
                        sendIcmpEchoPkt(dstIP, srcIP);
                    } else if (from.equals(srcIP) && to.equals(dstIP)) {
                        handler.cancel();
                        log.info("reachability approved!, icmp_seq = " + icmpSeq);
                        log.info("-------------------------------------------------");
                        latch.countDown();
                        internalPing();
                    }
                }
            }
        }
    }

    private void sendIcmpEchoPkt(Ip4Address src, Ip4Address dst) {
        Host srcHost = hostService.getHostsByIp(src).iterator().next();
        Host dstHost = hostService.getHostsByIp(dst).iterator().next();

        ICMPEcho echo = new ICMPEcho()
                .setIdentifier(++ident)
                .setSequenceNum(++seqNum);
        ICMP icmpPkt = (ICMP) new ICMP()
                .setIcmpType(ICMP.TYPE_ECHO_REQUEST)
                .setIcmpCode(ICMP.CODE_ECHO_REQEUST)
                .setChecksum((short) 0)
                .setPayload(echo);
        IPv4 ipv4Pkt = (IPv4) new IPv4()
                .setDscp((byte) 0)
                .setEcn((byte) 0)
                .setIdentification(ident)
                .setFlags((byte) 2)
                .setTtl((byte) 64)
                .setProtocol(IPv4.PROTOCOL_ICMP)
                .setSourceAddress(src.toInt())
                .setDestinationAddress(dst.toInt())
                .setPayload(icmpPkt);
        Ethernet ethPkt = (Ethernet) new Ethernet()
                .setSourceMACAddress(srcHost.mac())
                .setDestinationMACAddress(dstHost.mac())
                .setEtherType(Ethernet.TYPE_IPV4)
                .setPayload(ipv4Pkt);

        DefaultOutboundPacket pkt = new DefaultOutboundPacket(
                srcHost.location().deviceId(),
                DefaultTrafficTreatment.builder().setOutput(PortNumber.TABLE).build(),
                ByteBuffer.wrap(ethPkt.serialize()));
        packetService.emit(pkt);
    }

    private class TimeoutHandler extends TimerTask {
        @Override
        public void run() {
            log.info("TIMEOUT!");
            log.info("-------------------------------------------------");
            latch.countDown();
            internalPing();
        }
    }
}
