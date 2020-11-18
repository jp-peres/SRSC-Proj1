package socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utilitarios que estendem Utils1 e Utils2
 */
public class Utils3 {
    private static class FixedRand extends SecureRandom
    {
        MessageDigest	sha;
        byte[]	state;
        
        FixedRand()
        {
            try
            {
                this.sha = MessageDigest.getInstance("SHA-1");
                this.state = sha.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new RuntimeException("Nao existe suporte SHA-1!");
            }
        }
	
	    public void nextBytes(
	       byte[] bytes)
	    {
	        int	off = 0;
	        
	        sha.update(state);
	        
	        while (off < bytes.length)
	        {	            
	            state = sha.digest();
	            
	            if (bytes.length - off > state.length)
	            {
	                System.arraycopy(state, 0, bytes, off, state.length);
	            }
	            else
	            {
	                System.arraycopy(state, 0, bytes, off, bytes.length - off);
	            }
	            
	            off += state.length;
	            
	            sha.update(state);
	        }
	    }
    }
    
    /**
     * Retorna um SecureRandom de teste com o mesmo valor... 
     * @return  random fixo
     */
    public static SecureRandom createFixedRandom()
    {
        return new FixedRand();
    }
}
