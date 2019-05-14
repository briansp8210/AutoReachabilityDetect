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
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
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

    private Ip4Address srcIP;
    private Ip4Address dstIP;
    private DeviceId srcDevId;
    private Timer timer = new Timer();

    // For handling ICMP data.
    private static final int DEFAULT_MAX_COUNT = 5;
    private static final int DEFAULT_TIMEOUT_SECOND = 2;
    private CountDownLatch latch;
    private int count;
    private int timeout;
    private int sent;
    private static short icmpIdent = 0;
    private static short icmpSeqNum = 0;
    private ICMPTimeoutHandler icmpTimeoutHandler;

    // For handling TCP data.
    private static final short TCP_SYN_MASK = 0x0002;
    private static final short TCP_ACK_MASK = 0x0010;
    private static final int TCP_DEFAULT_TIMEOUT = 5;
    private boolean hasSynAcked;
    private int expSeq;
    private TCPTimeoutHandler tcpHandler;

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

    public void detect(Protocol proto, String srcIP, String dstIP) {
        this.srcIP = Ip4Address.valueOf(srcIP);
        this.dstIP = Ip4Address.valueOf(dstIP);
        srcDevId = hostService.getHostsByIp(this.srcIP).iterator().next()
                .location().deviceId();
        switch (proto) {
            case kICMP:
                icmpDetector(DEFAULT_MAX_COUNT, DEFAULT_TIMEOUT_SECOND);
                break;
            case kTCP:
                tcpDetector();
                break;
            case kUDP:
                udpDetector();
                break;
        }
    }

    private void icmpDetector(int count, int timeout) {
        this.timeout = timeout == 0 ? DEFAULT_TIMEOUT_SECOND : timeout;
        this.count = count == 0 ? DEFAULT_MAX_COUNT : count;
        sent = 0;
        latch = new CountDownLatch(this.count);

        log.info("+++++++++++++++++++++++++++++++++++++++++++++++++");
        log.info(srcIP.toString() + " PING " + dstIP.toString());

        installIcmpRule(this.dstIP, this.srcIP);
        installIcmpRule(this.srcIP, this.dstIP);
        log.info("installing rules...");
        waitRulesInstallation();
        ping();
        try {
            latch.await();
        } catch (InterruptedException e) {};
        flowRuleService.removeFlowRulesById(appId);
    }

    private void ping() {
        if (++sent > count) {
            log.info("+++++++++++++++++++++++++++++++++++++++++++++++++");
            return;
        }
        icmpTimeoutHandler = new ICMPTimeoutHandler();
        timer.schedule(icmpTimeoutHandler, timeout * 1000);
        log.info("-------------------------------------------------");
        log.info("Send Echo-Request to " + dstIP.toString() + ", icmp_seq = " + (icmpSeqNum + 1));
        sendIcmpEchoPkt(srcIP, dstIP);
    }

    private void installIcmpRule(Ip4Address src, Ip4Address dst) {
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

        flowObjectiveService.forward(srcDevId, forwardingObjective);
    }

    private void tcpDetector() {
        hasSynAcked = false;
        // Aim to capture SYN-ACK packet.
        installTcpRule(dstIP, srcIP);
    }

    private void udpDetector() {
        installUdpRule(dstIP, srcIP);
    }

    private void installTcpRule(Ip4Address ipv4Src, Ip4Address ipv4Dst) {
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchIPSrc(Ip4Prefix.valueOf(ipv4Src, Ip4Prefix.MAX_MASK_LENGTH))
                .matchIPDst(Ip4Prefix.valueOf(ipv4Dst, Ip4Prefix.MAX_MASK_LENGTH));
        if (ipv4Src.equals(srcIP)) {
            selectorBuilder.matchTcpDst(TpPort.tpPort(5001));
        } else {
            selectorBuilder.matchTcpSrc(TpPort.tpPort(5001));
        }

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.CONTROLLER)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(PacketPriority.MAX.priorityValue())
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .add();

        flowObjectiveService.forward(srcDevId, forwardingObjective);
    }

    private void installUdpRule(Ip4Address ipv4Src, Ip4Address ipv4Dst) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchIPSrc(Ip4Prefix.valueOf(ipv4Src, Ip4Prefix.MAX_MASK_LENGTH))
                .matchIPDst(Ip4Prefix.valueOf(ipv4Dst, Ip4Prefix.MAX_MASK_LENGTH))
                .matchUdpSrc(TpPort.tpPort(5001))
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

        flowObjectiveService.forward(srcDevId, forwardingObjective);
    }

    private void waitRulesInstallation() {
        while (flowRuleService.getFlowEntriesByState(
                srcDevId,
                FlowEntry.FlowEntryState.PENDING_ADD).iterator().hasNext());
    }

    private void waitRulesRemoval() {
        while (flowRuleService.getFlowEntriesByState(
                srcDevId,
                FlowEntry.FlowEntryState.PENDING_REMOVE).iterator().hasNext());
    }

    private class PktProcessor implements PacketProcessor {
        private PacketContext context;
        private Ethernet ethPkt;
        private IPv4 ipv4Pkt;
        private Ip4Address ipv4Src;
        private Ip4Address ipv4Dst;

        @Override
        public void process(PacketContext context) {
            this.context = context;
            ethPkt = context.inPacket().parsed();
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                ipv4Pkt = (IPv4)ethPkt.getPayload();
                ipv4Src = Ip4Address.valueOf(ipv4Pkt.getSourceAddress());
                ipv4Dst = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());

                if (ipv4Pkt.getProtocol() == IPv4.PROTOCOL_ICMP) {
                    icmpProcessor();
                } else if (ipv4Pkt.getProtocol() == IPv4.PROTOCOL_TCP) {
                    tcpProcessor();
                } else if (ipv4Pkt.getProtocol() == IPv4.PROTOCOL_UDP) {
                    udpProcessor();
                }
            }
            context.block();
        }

        private void icmpProcessor() {
            ICMP icmpPkt = (ICMP)ipv4Pkt.getPayload();
            int seqNum = ((ICMPEcho)icmpPkt.getPayload()).getSequenceNum();
            if (icmpPkt.getIcmpType() == ICMP.TYPE_ECHO_REPLY && seqNum == icmpSeqNum) {
                if (ipv4Src.equals(dstIP) && ipv4Dst.equals(srcIP)) {
                    log.info("Recv REPLY from {}, icmp_seq = {}", dstIP.toString(), seqNum);
                    log.info("Send ECHO to {}, icmp_seq = {}", srcIP.toString(), (icmpSeqNum + 1));
                    sendIcmpEchoPkt(dstIP, srcIP);
                } else if (ipv4Src.equals(srcIP) && ipv4Dst.equals(dstIP)) {
                    icmpTimeoutHandler.cancel();
                    log.info("Reachability approved!, icmp_seq = {}", seqNum);
                    latch.countDown();
                    ping();
                }
            }
        }

        private void tcpProcessor() {
            TCP tcpPkt = (TCP)ipv4Pkt.getPayload();
            int tcpSeqNum = tcpPkt.getSequence();
            int tcpAckNum = tcpPkt. getAcknowledge();
            boolean isSYN = (tcpPkt.getFlags() & TCP_SYN_MASK) != 0;
            boolean isACK = (tcpPkt.getFlags() & TCP_ACK_MASK) != 0;

            if (!hasSynAcked && isSYN && isACK) {
                hasSynAcked = true;
                expSeq = tcpAckNum;
                flowRuleService.removeFlowRulesById(appId);
                //waitRulesRemoval();
                // Aim to capture ACK packet, which completes handshaking.
                installTcpRule(srcIP, dstIP);
                //waitRulesInstallation();
                log.info("-------------------------------------------------");
                log.info("RECV SYN-ACK");
                log.info("TCP FLAGS: {}", tcpPkt.getFlags());
                log.info("TCP SEQNM: {}", Integer.toUnsignedString(tcpSeqNum));
                log.info("TCP ACKNM: {}", Integer.toUnsignedString(tcpAckNum));
                tcpHandler = new TCPTimeoutHandler();
                timer.schedule(tcpHandler, TCP_DEFAULT_TIMEOUT * 1000);
            } else if (!isSYN && isACK && tcpSeqNum == expSeq) {
                tcpHandler.cancel();
                log.info("RECV ACK");
                log.info("TCP FLAGS: {}", tcpPkt.getFlags());
                log.info("TCP SEQUE: {}", Integer.toUnsignedString(tcpSeqNum));
                log.info("TCP ACKNM: {}", Integer.toUnsignedString(tcpAckNum));
                log.info("-------------------------------------------------");
                flowRuleService.removeFlowRulesById(appId);
            }
            packetOut(context, PortNumber.TABLE);
        }

        private void udpProcessor() {
            UDP udpPkt = (UDP)ipv4Pkt.getPayload();
            if (ipv4Src.equals(dstIP) && ipv4Dst.equals(srcIP)) {
                log.info("**************************************");
                log.info("UDP pass phase1");
                flowRuleService.removeFlowRulesById(appId);
                installUdpRule(srcIP, dstIP);
                try {
                    Thread.sleep(5000);
                } catch(InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            } else if (ipv4Src.equals(srcIP) && ipv4Dst.equals(dstIP)) {
                log.info("UDP DSTPORT: " + udpPkt.getDestinationPort());
                log.info("UDP pass phase2");
                log.info("**************************************");
                flowRuleService.removeFlowRulesById(appId);
            }
        }
    }

    private void sendIcmpEchoPkt(Ip4Address src, Ip4Address dst) {
        Host srcHost = hostService.getHostsByIp(src).iterator().next();
        Host dstHost = hostService.getHostsByIp(dst).iterator().next();

        ICMPEcho echo = new ICMPEcho()
                .setIdentifier(++icmpIdent)
                .setSequenceNum(++icmpSeqNum);
        ICMP icmpPkt = (ICMP) new ICMP()
                .setIcmpType(ICMP.TYPE_ECHO_REQUEST)
                .setIcmpCode(ICMP.CODE_ECHO_REQEUST)
                //.setChecksum((short) 0)
                .setPayload(echo);
        IPv4 ipv4Pkt = (IPv4) new IPv4()
                .setDscp((byte) 0)
                .setEcn((byte) 0)
                .setIdentification(icmpIdent)
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

    private void packetOut(PacketContext context, PortNumber outPort) {
        context.treatmentBuilder().setOutput(outPort);
        context.send();
    }

    private class ICMPTimeoutHandler extends TimerTask {
        @Override
        public void run() {
            log.info("icmp_seq = {}, TIMEOUT!", icmpSeqNum);
            latch.countDown();
            ping();
        }
    }

    private class TCPTimeoutHandler extends TimerTask {
        @Override
        public void run() {
            log.info("{} TIMEOUT!", hasSynAcked ? "SYN-ACK" : "ACK");
            log.info("-------------------------------------------------");
        }
    }
}
