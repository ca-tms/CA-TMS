import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class SQLite {

	/**
	 * 
	 */
	Connection conn;

	public SQLite() {
		
		try {
			Class.forName("org.sqlite.JDBC");
		    conn= DriverManager.getConnection("jdbc:sqlite:WebPKI.db");
			 
		} catch (ClassNotFoundException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		} catch (SQLException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
		
	}
	
	
	public void InsertCert(String filepath)
	{
		
		int version;
		int serialnum;
		String sigalg;
		String issuer;
		String subject;
		Date notbefore;
		Date notafter;
		

		
		InputStream inStream;
		try {
		
			
			inStream = new FileInputStream(filepath);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			
			X509Certificate Cert = (X509Certificate)cf.generateCertificate(inStream);
			inStream.close();
			
			
			
			version=Cert.getVersion();
			serialnum=Cert.getSerialNumber().intValue();
			sigalg=Cert.getSigAlgName();
			issuer=Cert.getIssuerDN().getName();
			subject=Cert.getSubjectDN().getName();
			notbefore=Cert.getNotBefore();
			notafter=Cert.getNotAfter();
			
			Statement stat = conn.createStatement();
	
			

			String qeuery= "insert into Certificates values("+version+","+serialnum+",'"+sigalg+"','"+issuer+"','"+subject+"','"+notbefore+"','"+notafter+"','"+filepath+"');";
	
					stat.executeUpdate(qeuery);
			
			
			
			
		} catch (FileNotFoundException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		} catch (IOException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		} catch (SQLException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
		
		
		
		
	}
	
	public void showCertInfo(String Path)
	{
		try
		{
			
			InputStream inStream = new FileInputStream(Path);
			
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			
			X509Certificate oCert = (X509Certificate)cf.generateCertificate(inStream);
			inStream.close();
			SimpleDateFormat dateformat = new SimpleDateFormat("yyyy/MM/dd"); 
			String info = null;
			
			info = String.valueOf(oCert.getVersion());
			System.out.println("Version:"+info);
			
			info = oCert.getSerialNumber().toString(16);
			System.out.println("SerialNumber:"+info);
			
			Date beforedate = oCert.getNotBefore();
			info = dateformat.format(beforedate);
			System.out.println("NotBefore:"+info);
			Date afterdate = oCert.getNotAfter();
			info = dateformat.format(afterdate);
			System.out.println("NotAfter:"+info);
			
			info = oCert.getSubjectDN().getName();
			System.out.println("Subject:"+info); 
			
			info = oCert.getIssuerDN().getName();
			System.out.println("Issuer:"+info);	
			
			
			
			info = oCert.getSigAlgName();
			System.out.println("SigAlgName:"+info);
			System.out.print("Signature：");
			byte[] sign = oCert.getSignature();
			PrintHex(sign,sign.length);
			
			byte[] tbsCertificate = oCert.getTBSCertificate();
			System.out.print("DER Data:");
			PrintHex(tbsCertificate,tbsCertificate.length);
		}
		catch (Exception e) 
		{	 
			System.out.println("Error！");
			e.printStackTrace();
		}
	}//end showCertInfo
	public void PrintHex(byte data[],int len)
	{
		int i;
		int tmp;
		String Tmp="";	
		for(i=0; i<len; i++)
		{
			if(i%16 == 0)
			{
				System.out.println("");
				//0x0000
				if(i<0x10)
					Tmp = "0x000";
				if((i<0x100) && (i>=0x10))
					Tmp = "0x00";
				if((i>=0x100)&&(i<0x1000))
					Tmp = "0x0";
				if(i>=0x1000)
					Tmp = "0x";		
				System.out.print(Tmp+Integer.toHexString(i)+"h: ");	
			}
			tmp = data[i];
			if(tmp < 0)
				tmp = 256 + tmp;
			if(tmp <0x10)
				System.out.print("0"+Integer.toHexString(tmp) +" ");
			else
				System.out.print(Integer.toHexString(tmp) +" ");						
		}
		System.out.println("");
	}
	
	

	public static void main(String[] args) {
		
		SQLite sql=new SQLite();
		
			
			sql.InsertCert("E:\\Haixin\\Desktop\\1.cer");
			
	
			
		
	}

}
