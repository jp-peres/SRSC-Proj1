package socket;
import java.io.Serializable;

public class SSPPacket implements Serializable {

    private static final long serialVersionUID = 1L;
    private byte[] version = { 0x01, 0x01 };
    private byte contentType = 0x01; //0x01 SSP 0x02 SHP
    private byte payloadType = 0x01; //for SSP 0x01; for SHP 0x01 - Hello, 0x02- HelloResp, 0x03- KeyEst, 0x04- HandDone
    private int payloadSize;
    private byte[] ciphered;

    public SSPPacket(byte[] payload, byte contentType, byte payloadType, int payloadSize) {
        this.payloadSize = payloadSize;
        this.ciphered = payload;
        this.contentType = contentType;
        this.payloadType = payloadType;
    }
    
    public SSPPacket(byte[] payload, int payloadSize) {
        this.payloadSize = payloadSize;
        this.ciphered = payload;
    }

    public byte[] getVersion() {
        return this.version;
    }

    public byte getContentType(){
        return contentType;
    }


    public byte getPayloadType(){
        return payloadType;
    } 


    public int getPayloadSize(){
        return payloadSize;
    }

    public byte[] getPayload(){
        return ciphered;
    }
}