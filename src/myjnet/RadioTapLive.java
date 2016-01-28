// Linux command:
// >> java -classpath .:/media/sf_Downloads/MyJnet/jnetpcap.jar myjnet.MyRadioTapLive 250
// while in /../build//classes/


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package myjnet;

/**
 *
 * @author nri
 */
import java.util.ArrayList;
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapIf;  
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;  
import org.jnetpcap.nio.JBuffer;
import java.util.Scanner;

import java.util.Arrays;
import java.util.List;
import org.jnetpcap.PcapBpfProgram;




public class RadioTapLive {  
  
    static Scanner din;
    
    static List<PcapIf> alldevs = new ArrayList<PcapIf>();// Will be filled with NICs  
    static StringBuilder errbuf = new StringBuilder();// For any error msgs  
    static PcapIf device;
    
    static Pcap pcap;
    
    static int no_packets_iter;
    
    static long t_beacon_stamp;
    static long[] t_beacon = new long[2];
    static long[] t_system = new long[2];
    
    static long tot_system;
    static long tot_beacon;
    static long t_delta;
    
    static long t_track;
    static boolean is_hit = false;
    static int keep_count = 0;
    static final int max_count = 1;
    
    
    
    /** 
     * Main startup method 
     *  
     * @param args 
     *          ignored 
     */  
    public static void main(String[] args) {  
        
        if (max_count<=0)
            return;
                    
        // Defince an override for jpacket handler
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
            
            @Override
            public void nextPacket(PcapPacket packet, String user) {  
               
               //System.out.println(user);
               readPacket(packet);
                
                
            }  
        };
        
        din = new Scanner(System.in);        
        
        // Set number of packets to receive
        if (args.length!=0) {
            no_packets_iter = Integer.parseInt(args[0]);
        }
        else {
            no_packets_iter = 30; // default
        }
        
        /*************************************************************************** 
         * First get a list of devices on this system 
         **************************************************************************/  
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf  
                .toString());  
            return;  
        }    
        
        System.out.println("Network devices found: ");  
  
        
        // Print out the devices
        for (PcapIf dev : alldevs) {
            System.out.println("Dev: " + dev.toString());
        }
        
        // Print out device description
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
        }  

        System.out.println("\nMyDevice is maybe here: " + alldevs.get(5));
        
        // set main device  
        System.out.println("Choose device!");
        int dev_id = din.nextInt();
        device = alldevs.get(dev_id);
        
        
        System.out.println("getFlags: " + device.getFlags());
        
        System.out  
            .printf("\nChoosing '%s' on your behalf:\n",  
                (device.getDescription() != null) ? device.getDescription()  
                    : device.getName());  
  
        /*************************************************************************** 
         * Second we open up the selected device 
         **************************************************************************/  
        open_pcap();                   
        
        
        
        keep_count = 0;   
        is_hit = false;
                            
      
        long t_delta;
        long[] t_tmp = new long[2];
        int my_i = 0;
        
      
        for (int k = 0; k<no_packets_iter; k++) {
           
           
            pcap.loop(1, jpacketHandler, "Dispatched!");  
            
            
            
            /*
            if (keep_count==0) {
                keep_count = 1;
            }
            else if (keep_count==1) {
                 
                tot_system = t_system[1] -  t_system[0];
                
                tot_beacon = t_beacon[1] -  t_beacon[0];
                
                

                t_delta = tot_system-tot_beacon;
                
                System.out.println("delta sys: " + (tot_system) );
                System.out.println("delta beac: " + (tot_beacon) );
                System.out.println("delta : " + (tot_system-tot_beacon) );
                
                
                t_beacon[0] = t_beacon[1];
                t_system[0] = t_system[1];
            }
          */
            
                
                
            
        
        }
        
        
        /*************************************************************************** 
         * Last thing to do is close the pcap handle 
         **************************************************************************/  
        pcap.close();
        
        
    } 
    
    
    
    public static void readPacket(PcapPacket packet) {
        
        // Init
        int packet_size = packet.size();
        JBuffer packet_buf = packet;   
        
         // throw away first 40 bytes (magic number etc etc...)
        //  System.out.println("Throwing away Frame header!");
        // .getByteArray will itself skip frame header (40 bytes)
        byte[] data = packet_buf.getByteArray(0, packet_size);
        
        //System.out.printf("data size %d . packet size %d \n", data.length, packet_size);
        int max_byte_read = Math.min(packet_size, 32);
    
        /**
         * Keeping this section just for printing (dev)
         */
        if (false) {
            int i = 0;
            for (byte b : data) {

                if (i%16==0){

                    System.out.printf("%s: ", Integer.toHexString(i|0x100).substring(1));
                }

                if (b>=0) {
                    System.out.printf("%s ", Integer.toHexString(b|0x100).substring(1));
                    //System.out.printf("Byte : %s  Hex : %s\n", b, Integer.toHexString(b));
                }
                else {
                    System.out.printf("%s ", Integer.toHexString(256+b));
                    //System.out.printf("Byte : %s  Hex : %s\n", b, Integer.toHexString(256+b));
                }

                i++;
                if (i%16==0){
                    System.out.println("");
                }

                if (i>=max_byte_read){
                    System.out.println("");
                    break;
                }
            }
        }
         /**
        * 
        */
        int[] data_int = new int[max_byte_read];
        for (int k = 0; k<max_byte_read; k++) {
           data_int[k] = data[k]&0xFF;
        }

        byte[] frame_control = new byte[2];
        byte[] duration = new byte[2];
        byte[] dest_ip = new byte[6];
        byte[] src_ip = new byte[6];
        byte[] bss_id = new byte[6];
        byte[] seq_ctrl = new byte[2];
        
        byte[] time_stamp_bytes = new byte[8];
        byte[] time_stamp_bytes_tmp = new byte[8];        
        long time_stamp = 0;
        long tmp;
        long tmp2;
                
        byte[] beacon_interval = new byte[2];
        byte[] capability_info = new byte[2];
        byte[] tag_nr = new byte[1];
        byte[] tag_len = new byte[1];

        if (data_int[0]==0x80) {
            // It's a beacon
            //System.out.printf("It's a beacon!\n");
            frame_control = Arrays.copyOfRange(data, 0, 2);
            duration = Arrays.copyOfRange(data, 2, 4);
            dest_ip = Arrays.copyOfRange(data, 4, 10);
            src_ip = Arrays.copyOfRange(data, 10, 16);
            bss_id = Arrays.copyOfRange(data, 16, 22);
            seq_ctrl = Arrays.copyOfRange(data, 22, 24);
            
            
            time_stamp_bytes_tmp = Arrays.copyOfRange(data, 24, 32);
            for (int k = 0; k<8; k++) {
                time_stamp_bytes[k] = time_stamp_bytes_tmp[7-k];                
            }
            
            for (int k = 0; k<8; k++){
                tmp = (time_stamp_bytes[k]&0xFF);
                tmp2 = tmp<<((7-k)*8);
                time_stamp += tmp2;                
            }
            
            
            beacon_interval = Arrays.copyOfRange(data, 32, 34);
            capability_info = Arrays.copyOfRange(data, 34, 36);
            tag_nr = Arrays.copyOfRange(data, 36, 37);
            tag_len = Arrays.copyOfRange(data, 37, 38);

            int ss_id_len = tag_len[0];

            byte[] ss_id = new byte[ss_id_len];

            ss_id = Arrays.copyOfRange(data, 38, 38+ss_id_len);

            String str_ssid = "";
            //System.out.printf("SSID: ");
            for (byte b : ss_id) {
                int c = b&0xFF;
                //System.out.printf("%s", (char) c);    
                str_ssid += (char) c;
            }
                        
            
            if (str_ssid.compareTo("alienWs6")!=0) {
                System.out.println("                Skipped -> " + str_ssid + " possibly not connected?");
                return;
            } 
            else {
                System.out.println("SSID-> " + str_ssid);
            }
                
          
            // System.out.println("Time Stamp: " + time_stamp);
            
                        
            //System.out.printf("\n\n");
            t_beacon_stamp = time_stamp;
            if (keep_count==0) {
                t_beacon[0] = time_stamp/1000;
                t_system[0] = System.currentTimeMillis();

            } 
            else if (keep_count==1) {
                is_hit = true;

                t_beacon[1] = time_stamp/1000;
                t_system[1] = System.currentTimeMillis();
                

            }     
            
            if (keep_count==0) {
                keep_count = 1;
            }
            else if (keep_count==1) {
                 
                tot_system = t_system[1] -  t_system[0];
                
                tot_beacon = t_beacon[1] -  t_beacon[0];
                
                

                t_delta = tot_system-tot_beacon;
                
                System.out.println("delta sys: " + (tot_system) );
                System.out.println("delta beac: " + (tot_beacon) );
                System.out.println("delta : " + (tot_system-tot_beacon) );
                System.out.println("");
                
                t_beacon[0] = t_beacon[1];
                t_system[0] = t_system[1];
            }
          
                
          
            
        }
        else {
            System.out.println("Not a beacon unfortunately (damn filter...) \n\n");
          
        }
        
            
        
    }
    
    
    private static boolean open_pcap() {
        
              
        int snaplen = 80;//64*1024;           // Capture all packets, no trucation  
        
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 1*0;// * 300;           // 10 seconds in millis  
        pcap =  
            Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
        
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return false;  
        }  
        
        // We set a filter here. If filter is not set, snaplen will not work!
        // Regardless, it's good to have a filter.
        PcapBpfProgram bpf = new PcapBpfProgram();        
        int optim = 0;
        int netm = 0xFFFFFF00; // Not sure if this has an effect!?

        String compStr = "link[0]==0x80";

        // Compile the filter
        int retFilterCompiler = pcap.compile(bpf, compStr, optim, netm);
        
        int retSetFilter = pcap.setFilter(bpf);
        if (retSetFilter==-1) {
            // double check to see that compiler also gave an error
            if (retFilterCompiler==Pcap.OK){
                System.out.println("Strange... Compiler error missing!");
            }
            System.out.println("SetFilter FAILED");
            System.err.println(pcap.getErr());
            
            // We dont want to continue. Return
            return false;
        }
        else {
            // All good
            System.out.println("\nSetFilter SUCCEED -> " + compStr + "\n");
        }
        
          
        
        return true;
    }
    
}  
