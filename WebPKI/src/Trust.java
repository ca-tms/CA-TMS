import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

class TrustAss{
	PublicKey k;
	String ca;
	int[] S;
	float[] Okl;
	float[] Oit;
	/**
	 * 
	 */
	public TrustAss(PublicKey ik,String ica,int[] iS,float[] iOkl,float[] iOit) {
		k=ik;
		ca=ica;
		S=iS;
		Okl=iOkl;
		Oit=iOit;


	}
	public PublicKey getK() {
		return k;
	}
	public String getCa() {
		return ca;
	}
	public int[] getS() {
		return S;
	}
	public void setS(int[] s) {
		S = s;
	}
	public float[] getOkl() {
		return Okl;
	}
	public float[] getOit() {
		return Oit;
	}
	
}

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
	
	public float[] ANDfunction(float[] a,float[] b)
	{
		float Ta,Tb,Tanb,Ca,Cb,Canb,Fa,Fb,Fanb;
		float[] result= new float[3];

		Ta=a[0];Tb=b[0];
		Ca=a[1];Cb=b[1];
		Fa=a[2];Fb=b[2];
		
		Fanb=Fa*Fb;
		
		Canb=Ca+Cb-(Ca*Cb)-((((1-Ca)*Cb*(1-Fa)*Tb)+(Ca*(1-Cb)*(1-Fb)*Ta))/(1-Fa*Fb));
		
		if(Canb==0)
			Tanb=(float)0.5;
		else
			Tanb=(1/Canb)*((Ca*Cb*Ta*Tb)+(((Ca*(1-Cb)*(1-Fa)*Fb*Ta)+((1-Ca)*Cb*Fa*(1-Fb)*Tb))/(1-Fanb)));
		
		result[0]=Tanb;
		result[1]=Canb;
		result[2]=Fanb;
		
		return result;
		
	}
	
	public boolean within(int[] a, int b)
	{
		for(int i=0;i<a.length;i++)
		{
			if(a[i]==b) return true;
		}
		return false;
	}
	
	public int[] insertint(int[] a, int b)
	{
		int[] result = new int[a.length+1];
		for(int i=0;i<a.length;i++)
		{
			result[i]=a[i];
		}
		result[a.length]=b;
		return result;
	}
	
	public boolean withinTL(List<TrustAss> TL, TrustAss TA)
	{
		TrustAss temp;
		for(int i=1;i<=TL.size();i++)
		{
			temp=TL.get(i);
			if(temp.getK().equals(TA.getK())&&temp.getCa().equals(TA.getCa()))
				return true;
		}
		
		return false;
	}
	
	public TrustAss InitTrustAss(PublicKey k,String ca)
	{
		int[] S=new int[1];
		String issuer;
		ResultSet rs;
		float Okl[]=new float[3];
		TrustAss TA;
		
		
		if(sql.isKCAExisted(k, ca))
			return null;
		
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
		
		boolean a=sql.InsertTA(k, ca, S, Okl, Oit);
		
		if(a)
			{
			TA=new TrustAss(k,ca,S,Okl,Oit);
			return TA;
			}
		else return null;

	}
	
	
	//retuen int means if =1 Trusted ,=0 unknown, =-1 Untrusted
	public int TrustValid(CertPath path,float SecLevel,float rc/*,int[] ValidServ*/)
	{
		int n,v,h;
		int R=0;
		float exp;
		float[] temp=new float[3];
		float[] Okln=new float[3];
		TrustAss TAtemp;;
		List<TrustAss> TL= new ArrayList<TrustAss>();
		List<X509Certificate> list = (List<X509Certificate>) path.getCertificates();
		n=list.size();
		X509Certificate Cert=list.get(n);
		//////check 1////////
		v=sql.isCertVaild(Cert);
		if(v>0)
				return 1;
			
		//////check 1////////
		//////check 2////////
		
		for(int i=1;i<=n;i++)
		{
			v=sql.isCertVaild(list.get(i));
			if(v<0)
				return -1;
		}
		//////check 2////////
		/////3B////////////////////////////
		
		for(int i=1;i<=n;i++)
		{
			Cert=list.get(i);
			TAtemp=InitTrustAss(Cert.getPublicKey(),Cert.getSubjectDN().getName());
			if(TAtemp!=null)
				TL.add(TAtemp);
			TAtemp=null;
		}
		/////3B////////////////////////////
		/////3D////////////////////////////
		h=1;
		for(int i=1;i<=n;i++)
		{
			temp=sql.getAssOkl(list.get(i).getPublicKey(), list.get(i).getSubjectDN().getName());
			if((temp!=null)&&(temp[0]==1)&&(temp[1]==1)&&(temp[2]==1))
				h=i;
		}
		
		/////3D////////////////////////////
		/////3E////////////////////////////
		
		Okln=sql.getAssOit(list.get(n-1).getPublicKey(), list.get(n-1).getSubjectDN().getName());
		for(int i=h;i<n-1;i++)
		{
			Okln=ANDfunction(Okln,sql.getAssOit(list.get(h).getPublicKey(), list.get(h).getSubjectDN().getName()));
		}
		/////3E////////////////////////////
		/////3F////////////////////////////
		exp=Efunction(Okln);
		/////3F////////////////////////////
		/////3GH////////////////////////////
		if(exp>=SecLevel)
			R=1;
		else
		{
			if(Okln[1]>=rc)
				R=-1;
		/////3GH////////////////////////////
		/////3I////////////////////////////
			else
			{
				//to be done about the 3I function
			}
		}
		/////3I////////////////////////////
		/////3j////////////////////////////
		UpdateView( path, R, TL);
		/////3j////////////////////////////
		
		return R;
	}
	
	public void UpdateView(CertPath path,int R,List<TrustAss> TL/*,List of Validation???*/)
	{
		List<X509Certificate> list = (List<X509Certificate>) path.getCertificates();
		TrustAss Assi,Assii;
		int id;
		int[] Si;
		////////1////////////////////////
		if(R==0)
			return;
		////////1////////////////////////
		////////3////////////////////////
		if(R>0)
		{
			for(int i=1;i<=list.size();i++)
			{
				Assi=sql.getAss(list.get(i).getPublicKey(),list.get(i).getSubjectDN().getName());
				id=sql.getCertID(list.get(i).getPublicKey(),list.get(i).getSubjectDN().getName());
				if(!within(Assi.getS(),id))
				{
		/////////////////3a//////////////////////////////////
					Si=insertint(Assi.getS(),id);
					Assi.setS(Si);
		/////////////////3a//////////////////////////////////		
		/////////////////3b//////////////////////////////////
					if(withinTL(TL,Assi))
						sql.InsertTA(Assi.getK(), Assi.getCa(), Assi.getS(), Assi.getOkl(), Assi.getOit());
				}
	/////////////////3b/////////////////////////////////////
	/////////////////3c/////////////////////////////////////	
				Assii=sql.getAss(list.get(i+1).getPublicKey(),list.get(i+1).getSubjectDN().getName());
				if(withinTL(TL,Assii))
				{
					//update oiti with positive experience
				}
	/////////////////3c/////////////////////////////////////
			}//for ,3
		}//if ,3
		
		if(R<0)
		{
			// don't know jet how to deal with the VS1...VSn
			//the whole step 4 is to be done
		}//if ,4
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
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (IOException e) {

				e.printStackTrace();
			}
		

	}

}
