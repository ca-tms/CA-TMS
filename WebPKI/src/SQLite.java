import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
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
	Statement stat;

	public SQLite() {
		
		try {
			Class.forName("org.sqlite.JDBC");
		    conn= DriverManager.getConnection("jdbc:sqlite:WebPKI.db");
		    stat = conn.createStatement();
			 
		} catch (ClassNotFoundException e) {
			
			e.printStackTrace();
		} catch (SQLException e) {

			e.printStackTrace();
		}
		
	}
	
	
	public X509Certificate LoadCert(String filepath)
	{
		InputStream inStream;
		X509Certificate Cert=null;
		
		try {
			inStream = new FileInputStream(filepath);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			
			 Cert = (X509Certificate)cf.generateCertificate(inStream);
			inStream.close();
			
			
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return Cert;
	}
	
	public void InsertCert(String filepath)
	{
		
		int version;
		int serialnum;
		String sigalg;
		String issuer;
		String subject;
		String publickey;
		java.sql.Date notbefore;
		java.sql.Date notafter;
		

		
		try {
			X509Certificate Cert=LoadCert(filepath);
		
			version=Cert.getVersion();
			serialnum=Cert.getSerialNumber().intValue();
			sigalg=Cert.getSigAlgName();
			issuer=Cert.getIssuerDN().getName();
			subject=Cert.getSubjectDN().getName();
			publickey=Cert.getPublicKey().toString();
			notbefore = new java.sql.Date(Cert.getNotBefore().getTime());
			notafter = new java.sql.Date(Cert.getNotAfter().getTime());
			

			String qeuery= "insert into Certificates values((SELECT max(ID) FROM Certificates)+1,"+version+","+serialnum+",'"+sigalg+"','"+issuer+"','"+subject+"','"+publickey+"','"+notbefore+"','"+notafter+"','"+filepath+"');";
	
					stat.executeUpdate(qeuery);
			
			
			
		} catch (SQLException e) {
			
			e.printStackTrace();
		}
		
	}
	
	
	public boolean InsertTA(PublicKey k,String ca,int[] S,float[] Okl,float[] Oit)
	{
		String publickey;
		String Ss="";
		String Okls="";
		String Oits="";
		String qeuery;
		
		publickey=k.toString();
		

		
		for(int i=0;i<S.length;i++)
		{Ss=Ss+S[i]+",";}
		
		if(Okl==null)
			Okls="unknown";
			else
		{for(int i=0;i<3;i++)
		{Okls=Okls+Okl[i]+",";}}
		
		for(int i=0;i<3;i++)
		{Oits=Oits+Oit[i]+",";}
		
		
		
		try {
			
			qeuery= "SELECT count(*) FROM Assessment WHERE k='"+publickey+"' AND ca='"+ca+"';";
			ResultSet rs = stat.executeQuery(qeuery);
			
			if(rs.getInt(1)>0)
			{System.out.println("Certificate for the Key not existed");
				return false;}
			
		 qeuery= "insert into Assessment values('"+publickey+"','"+ca+"','"+Ss+"','"+Okls+"','"+Oits+"');";

					stat.executeUpdate(qeuery);
					return true;
		} catch (SQLException e) {
			
			e.printStackTrace();
			return false;
		}
		
		

	}
	
	
	public boolean isKCAExisted(PublicKey k,String ca)
	{
		
		
		
		try {
			

			String qeuery= "SELECT COUNT(*) FROM Assessment WHERE k='"+k.toString()+"' AND ca='"+ca+"';";

			ResultSet rs = stat.executeQuery(qeuery);
			if(rs.getInt(1)==0)
				return false;
			else
				return true;
			
		} catch (SQLException e) {
			
			e.printStackTrace();
			return false;
		}
	}
	
	
	public boolean isRootCA(String ca)
	{
		
		try {
			

			String qeuery= "SELECT Issuer,Subject FROM Certificates WHERE Subject='"+ca+"';";

			ResultSet rs = stat.executeQuery(qeuery);
			if(!rs.next())
			{System.out.println("Certificate not existed");
				return false;}
			else
			{
				if(rs.getString("Issuer").equals(rs.getString("Subject")))
					return true;
				else
					return false;
			}
				
			
		} catch (SQLException e) {
			
			e.printStackTrace();
			return false;
		}
	}
	
	public float[] split(String input)
	{
		String[] out=null;
		
		if(!input.contains(","))
			return null;
		
		out = input.split(","); 
		
		float result[]= new float[out.length];
		for(int i=0;i<out.length;i++)
		{
			result[i]=Float.parseFloat(out[i]);
		}
		
		return result;
	}
	
	public int[] splitint(String input)
	{
		String[] out=null;
		
		if(!input.contains(","))
			return null;
		
		out = input.split(","); 
		
		int result[]= new int[out.length];
		for(int i=0;i<out.length;i++)
		{
			result[i]=Integer.parseInt(out[i]);
		}
		
		return result;
	}
	
	public String getCertSet(PublicKey k)
	{
	
		try {
			
			String S="";
			String qeuery= "SELECT *, count(ID) FROM Certificates WHERE PublicKey='"+k.toString()+"';";

			ResultSet rs = stat.executeQuery(qeuery);
			if(rs.getInt(2)==0)
			{System.out.println("Certificate for the Key not existed");
				return "";}
			
			 while (rs.next()){
				 S=S+rs.getInt(1)+",";
			 }
				
			return S;
		} catch (SQLException e) {
			
			e.printStackTrace();
			return "";
		}
	}
	
	public String getCertIssuer(PublicKey k,String subject)
	{	
		String iss=null;
	
		try {
			
			String qeuery= "SELECT Issuer, count(Issuer) FROM Certificates WHERE PublicKey='"+k.toString()+"' AND Subject='"+subject+"';";


			 ResultSet rs = stat.executeQuery(qeuery);
			if(rs.getInt(2)==0)
			{System.out.println("Certificate for the Key not existed");
				return iss;}
				
			return rs.getString(1);
		} catch (SQLException e) {
			
			e.printStackTrace();
			return iss;
		}
	}
	
	public int getCertID(PublicKey k,String subject)
	{	
		int id=-1;
	
		try {
			
			String qeuery= "SELECT ID, count(ID) FROM Certificates WHERE PublicKey='"+k.toString()+"' AND Subject='"+subject+"';";


			 ResultSet rs = stat.executeQuery(qeuery);
			if(rs.getInt(2)==0)
			{System.out.println("Certificate for the Key not existed");
				return id;}
				
			return rs.getInt(1);
		} catch (SQLException e) {
			
			e.printStackTrace();
			return id;
		}
	}

	
	//return int means =1 Trusted, =-1 Untrusted, =0 unknown
	public int isCertVaild(X509Certificate Cert)
	{	
		
	
		try {
			
			String qeuery= "SELECT count(ID) FROM Tcert t left join Certificates c on t.TID=c.ID WHERE SerialNum='"+Cert.getSerialNumber().intValue()+"' AND Issuer='"+Cert.getIssuerDN().getName()+"';";


			 ResultSet rs = stat.executeQuery(qeuery);
			if(rs.getInt(1)>=1)
				return 1;
			
			 qeuery= "SELECT count(ID) FROM uTcert t left join Certificates c on t.uTID=c.ID WHERE SerialNum='"+Cert.getSerialNumber().intValue()+"' AND Issuer='"+Cert.getIssuerDN().getName()+"';";
	
			 if(rs.getInt(1)>=1)
					return -1;
			 
			 return 0;
		} catch (SQLException e) {
			
			e.printStackTrace();
			return 0;
		}
	}
	
	public ResultSet getSameIssuerOitSet(String issuer)
	{ 	ResultSet rs=null;
try {
			
			String qeuery= "SELECT Oit ,COUNT(Oit) FROM Assessment a left join Certificates c on a.k=c.PublicKey AND a.ca=c.Subject WHERE c.Issuer='"+issuer+"';";

			 rs = stat.executeQuery(qeuery);
		
				
			return rs;
		} catch (SQLException e) {
			
			e.printStackTrace();
			return rs;
		}
	}
	
	public float[] getAssOkl(PublicKey k,String ca)
	{
	
		try {
			
			
			String qeuery= "SELECT Okl , COUNT(Okl) FROM Assessment WHERE PublicKey='"+k.toString()+"' AND Subject='"+ca+"';";

			ResultSet rs = stat.executeQuery(qeuery);
			if(rs.getInt(2)==0)
			{System.out.println("Assessment for the Key not existed");
				return null;}
			
			 float[] res=new float[3];
			 res=split(rs.getString(1));
				
			return res;
		} catch (SQLException e) {
			
			e.printStackTrace();
			return null;
		}
	}
	
	public float[] getAssOit(PublicKey k,String ca)
	{
	
		try {
			
			
			String qeuery= "SELECT Oit , COUNT(Oit) FROM Assessment WHERE PublicKey='"+k.toString()+"' AND Subject='"+ca+"';";

			ResultSet rs = stat.executeQuery(qeuery);
			if(rs.getInt(2)==0)
			{System.out.println("Assessment for the Key not existed");
				return null;}
			
			 float[] res=new float[3];
			 res=split(rs.getString(1));
				
			return res;
		} catch (SQLException e) {
			
			e.printStackTrace();
			return null;
		}
	}
	
	public TrustAss getAss(PublicKey k,String ca)
	{
try {
			
		TrustAss TA;
			String qeuery= "SELECT * , COUNT(Oit) FROM Assessment WHERE PublicKey='"+k.toString()+"' AND Subject='"+ca+"';";

			ResultSet rs = stat.executeQuery(qeuery);
			if(rs.getInt(2)==0)
			{System.out.println("Assessment for the Key not existed");
				return null;}
			
			 
			float[] Okl,Oit;
			int[] s;
			 s=splitint(rs.getString(3));
			 Okl=split(rs.getString(4));
			 Oit=split(rs.getString(5));
			 
			 TA=new TrustAss(k,ca,s,Okl,Oit);
			return TA;
		} catch (SQLException e) {
			
			e.printStackTrace();
			return null;
		}
	}
	
	public void untrustCert(X509Certificate Cert)
	{
try {
			
		
			String qeuery= "SELECT ID , COUNT(Oit) FROM Certificates WHERE SerialNum='"+Cert.getSerialNumber().intValue()+"' AND Issuer='"+Cert.getIssuerDN().getName()+"';";

			ResultSet rs = stat.executeQuery(qeuery);
			if(rs.getInt(2)==0)
			{System.out.println("Certificate not existed");
				return ;}
			
			 
		int id=rs.getInt(1);
		
		 qeuery= "insert into uTcert values("+id+");";

			stat.executeUpdate(qeuery);
		
		} catch (SQLException e) {
			
			e.printStackTrace();
			return ;
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
			System.out.print("Signature£º");
			byte[] sign = oCert.getSignature();
			PrintHex(sign,sign.length);
			
			byte[] tbsCertificate = oCert.getTBSCertificate();
			System.out.print("DER Data:");
			PrintHex(tbsCertificate,tbsCertificate.length);
		}
		catch (Exception e) 
		{	 
			System.out.println("Error£¡");
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
				String rs= sql.getCertIssuer(k, ca);
				
				
					System.out.println(rs);
			
				
			} catch (FileNotFoundException e) {
	
				e.printStackTrace();
			} catch (CertificateException e) {

				e.printStackTrace();
			} catch (IOException e) {
				
				e.printStackTrace();
			}
		
	
	
			
		
	}

}
