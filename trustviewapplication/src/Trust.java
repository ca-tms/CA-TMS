import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;


public class Trust {
	SQLite sql;
	
	public Trust()
	{
		 sql=new SQLite();
		
	
	}
	
	public float[] split(String input)
	{
		String[] out=null;
		
		
		out = input.split(","); 
		
		float result[]= new float[out.length];
		for(int i=0;i<out.length;i++)
		{
			result[i]=Float.parseFloat(out[i]);
		}
		
		return result;
	}
	
	public float[] OitSetCal(ResultSet rs)
	{
		List<float[]> Oitset =new ArrayList<float[]>();
		String temp;
		float f=0;
		float Oit[]=null;
		
		try {	
			if(rs.getInt(2)==0)
				{Oit =new float[3];
				Oit[0]=(float)0.5;
				Oit[1]=(float)0;
				Oit[2]=(float)0.5;
				return Oit;}
			
			
				while(rs.next())
				{
					temp=rs.getString(1);	
					Oitset.add(split(temp));
				}
				
				for(int i=0;i<Oitset.size();i++)
				{
					f=f+Efunction(Oitset.get(i));
				}
				f=f/Oitset.size();
				
			    Oit =new float[3];
				Oit[0]=(float)0.5;
				Oit[1]=(float)0;
				Oit[2]=(float)f;
				
				return Oit;
			
			} catch (SQLException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
				return Oit;
			}
			
	}
	
	
	public float Efunction(float[] input)
	{
		float t,c,f,r;
		t=input[0];
		c=input[1];
		f=input[2];
		
		r=t*c+f*(1-c);
		return r;
	}
	
	public void InitTrustAss(PublicKey k,String ca)
	{
		int[] S=new int[1];
		String issuer;
		ResultSet rs;
		float Okl[]=new float[3];
		
		
		
		if(sql.isKCAExisted(k, ca))
			return;
		
		if(sql.isRootCA(ca))
		{ 
		Okl[0]=(float)1.0;
		Okl[1]=(float)1.0;
		Okl[2]=(float)1.0;
		}
		else
		Okl=null;
		
		S[0]=sql.getCertID(k,ca);
		
		issuer=sql.getCertIssuer(k, ca);
		rs=sql.getSameIssuerOitSet(issuer);

		float Oit[]=OitSetCal(rs);
		
		sql.InsertTA(k, ca, S, Okl, Oit);
		

	}
	
	public static void main(String[] args) {
		SQLite sql=new SQLite();
		Trust t=new Trust();
		
		InputStream inStream;

		
			
			try {
				inStream = new FileInputStream("E:\\Haixin\\Desktop\\2.cer");
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				
				X509Certificate Cert = (X509Certificate)cf.generateCertificate(inStream);
				inStream.close();
				
				
				PublicKey k;
				k=Cert.getPublicKey();
				
				String ca= Cert.getSubjectDN().getName();
				String issuer= Cert.getIssuerDN().getName();
				
				int Ss[]=new int[1] ;
				Ss[0]=1;
				
				float Okls[]={(float)1.0,(float)1.0,(float)1.0};
				
				
				float[] Oits= new float[3];
				
				//sql.InsertTA(k, ca, Ss, Okls, Oits);
			//	sql.InsertCert("E:\\Haixin\\Desktop\\5.cer");
				//System.out.print(sql.getCertSet(k));
				//String rs= sql.getCertIssuer(k, ca);
				
				t.InitTrustAss(k, ca);
				
			
				
			} catch (FileNotFoundException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
			} catch (IOException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
			}
		

	}

}
