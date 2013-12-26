import java.security.*;
import java.io.*;
import java.util.*;
import java.security.cert.*;


public class PathVerifier {
	public PathVerifier()
	{}
	public X509Certificate getCert(String path) throws IOException, CertificateException
	{
		InputStream inStream;
		inStream = new FileInputStream(path);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
			
				
				X509Certificate Cert = (X509Certificate)cf.generateCertificate(inStream);
				
				inStream.close();
				return Cert;
	
			
			
		
		
	}
	
	public  boolean CertValid(X509Certificate Cert)
	{
		
		try {
			
			Date TimeNow=new Date();

			Cert.checkValidity(TimeNow);
			  System.out.println("OK");
			  return true;
			
		}  catch (CertificateExpiredException e) {
			
			System.out.println("Expired"); 
			e.printStackTrace();
			return false;
		} catch (CertificateNotYetValidException e) {
			System.out.println("Not yet valid");
			e.printStackTrace();
			return false;
		}
	}
		
		public  boolean PathValid( CertPath path)
		{
			X509Certificate issuer,subject;
			List<X509Certificate> list = (List<X509Certificate>) path.getCertificates();
			
			if(list.isEmpty())
			{//to be done}
				return false;
			}
			
			if(list.size()==1)
			{
				return CertValid(list.get(0));
			}
			
			issuer=list.get(0);
			PublicKey pbk;
			
			for(int i=1 ;i<list.size();i++)
			{
				pbk=issuer.getPublicKey();
				subject=list.get(i);
				try {
					subject.verify(pbk);
				} catch (InvalidKeyException e) {

					e.printStackTrace();
					return false;
				} catch (CertificateException e) {
					
					e.printStackTrace();
					return false;
				} catch (NoSuchAlgorithmException e) {
					
					e.printStackTrace();
					return false;
				} catch (NoSuchProviderException e) {
				
					e.printStackTrace();
					return false;
				} catch (SignatureException e) {
					
					e.printStackTrace();
					return false;
				}
				
				if(i==list.size()-1)
				{return true;}
				
				issuer=list.get(i);
				subject=list.get(i+1);
			}
			return true;
		}
}
