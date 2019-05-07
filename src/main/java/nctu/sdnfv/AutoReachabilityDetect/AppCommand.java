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

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.onlab.packet.Ip4Address;
import org.onosproject.cli.AbstractShellCommand;
import nctu.sdnfv.AutoReachabilityDetect.AppComponentService;


/**
 * Sample Apache Karaf CLI command
 */
@Command(scope = "onos", name = "ping",
         description = "Sample Apache Karaf CLI command")
public class AppCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "source", required = true)
    String srcIP;

    @Argument(index = 1, name = "destination", required = true)
    String dstIP;

    @Option(name = "-c", description = "Number of ECHO packets to send.",
            required = false)
    int count;

    @Option(name = "-W", description = "Time to wait for a response (in seconds).",
            required = false)
    int timeout;

    @Override
    protected void execute() {
        AppComponentService app = get(AppComponentService.class);
        app.ping(srcIP, dstIP, count, timeout);
    }
}
