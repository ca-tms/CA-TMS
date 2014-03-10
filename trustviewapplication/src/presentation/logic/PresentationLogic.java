package presentation.logic;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import data.Configuration;
import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

public class PresentationLogic {
	
	public static X509Certificate LoadCert(String filepath) throws CertificateException, IOException 
	{
		InputStream inStream;
		X509Certificate Cert=null;
		
	
			inStream = new FileInputStream(filepath);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			
			 Cert = (X509Certificate)cf.generateCertificate(inStream);
			inStream.close();
		return Cert;
	}
	
	///////////////////////////////////////////////////////////refresh_TC_Table/////////////////////////////////////////////////////////////////////////////////////
	@SuppressWarnings({ "deprecation", "serial" })
	public static DefaultTableModel refresh_TC_Table()
	{

		DefaultTableModel Model = new DefaultTableModel(
				new Object[][] {}, new String[] { "Serial", "Issuer",
						"Subject", "PublicKey" , "NotBefore", "NotAfter"}) {
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] { String.class, String.class,
					String.class, String.class, String.class, String.class };

			@SuppressWarnings({ "rawtypes", "unchecked" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}

			boolean[] columnEditables = new boolean[] { false, false, false,false,false,
					false };

			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		};
		
		
		Collection<TrustCertificate> Certs_temp = null;

		try {
			TrustView view = data.Model.openTrustView();
			Certs_temp = view.getTrustedCertificates();
			view.close();

		} catch (Exception e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
		}

		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate Certificate;

		while (it_cert.hasNext()) {
			Certificate = (TrustCertificate) it_cert.next();

			Model.addRow(new Object[] {
					Certificate.getSerial(), Certificate.getIssuer(),
					Certificate.getSubject(), Certificate.getPublicKey(), Certificate.getNotBefore().toGMTString(), Certificate.getNotAfter().toGMTString() });
			
		}
		
	   return Model;
	}
	

///////////////////////////////////////////////////////////refresh_uTC_Table/////////////////////////////////////////////////////////////////////////////////////

	@SuppressWarnings({ "serial", "deprecation" })
	public static DefaultTableModel refresh_uTC_Table()
	{
		DefaultTableModel Model = new DefaultTableModel(
				new Object[][] {}, new String[] { "Serial", "Issuer",
						"Subject", "PublicKey" , "NotBefore" , "NotAfter" }) {
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] { String.class, String.class,
					String.class, String.class, String.class, String.class };

			@SuppressWarnings({ "rawtypes", "unchecked" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}

			boolean[] columnEditables = new boolean[] { false,false,false, false, false,
					false };

			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		};

		Collection<TrustCertificate> Certs_temp=null;
		try {
			TrustView view = data.Model.openTrustView();
			Certs_temp = view.getUntrustedCertificates();
			view.close();

		} catch (Exception e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
		}

		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate Certificate;
		while (it_cert.hasNext()) {
			 Certificate = (TrustCertificate) it_cert.next();

			 Model.addRow(new Object[] {
					Certificate.getSerial(), Certificate.getIssuer(),
					Certificate.getSubject(), Certificate.getPublicKey(), Certificate.getNotBefore().toGMTString(), Certificate.getNotAfter().toGMTString() });

		}
		return Model;
	}
///////////////////////////////////////////////////////////refresh_Ass_Table/////////////////////////////////////////////////////////////////////////////////////
	
	@SuppressWarnings("serial")
	public static DefaultTableModel refresh_Ass_Table()
	{
		DefaultTableModel Model = new DefaultTableModel(
				new Object[][] {}, new String[] { "PublicKey", "CA",
						"TrustCertificate", "O_kl", "O_it_ca", "O_it_ee" }) {
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] { String.class, String.class,
					String.class, String.class, String.class, Object.class };

			@SuppressWarnings({ "rawtypes", "unchecked" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}

			boolean[] columnEditables = new boolean[] { false, false, false,
					false, true, true };

			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		};

		Collection<TrustAssessment> Assessments_temp = null;
		try {
			TrustView view = data.Model.openTrustView();
			Assessments_temp = view.getAssessments();
			view.close();

		} catch (Exception e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
		}

		Iterator<TrustAssessment> it_ass = Assessments_temp.iterator();
		TrustAssessment Assessment;

		while (it_ass.hasNext()) {
			Assessment = (TrustAssessment) it_ass.next();
			String S = "";
			for (TrustCertificate s : Assessment.getS())
				S += S.isEmpty() ? s : ", " + s;
			S = "{" + S + "}";
			String o_kl = "";
			o_kl += Assessment.getO_kl().isSet() ? "("
					+ Assessment.getO_kl().get().getT() + ", "
					+ Assessment.getO_kl().get().getC() + ", "
					+ Assessment.getO_kl().get().getF() + ")" : "unknown";

			String o_it_ca = "(" + Assessment.getO_it_ca().getT() + ", "
					+ Assessment.getO_it_ca().getC() + ", "
					+ Assessment.getO_it_ca().getF() + ")";
			String o_it_ee = "(" + Assessment.getO_it_ee().getT() + ", "
					+ Assessment.getO_it_ee().getC() + ", "
					+ Assessment.getO_it_ee().getF() + ")";

			Model.addRow(new Object[] { Assessment.getK(),
					Assessment.getCa(), S, o_kl, o_it_ca, o_it_ee });

		}
		return Model;
	}


///////////////////////////////////////////////////////////getTCert_by_Click/////////////////////////////////////////////////////////////////////////////////////
	public static TrustCertificate getTCert_by_Click(JTable table)

	{
		String Serial="";
		String Issuer="";		
		int row =table.getSelectedRow();
		if(row==-1) return null;
		Serial=(String)table.getValueAt(row, 0);
		Issuer=(String)table.getValueAt(row, 1);
		
		Collection<TrustCertificate> Certs_temp = null;

		try {
			TrustView view = data.Model.openTrustView();
			Certs_temp = view.getTrustedCertificates();
			view.close();

		} catch (Exception e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
			return null;
		}
	
		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate Certificate=null;

		while (it_cert.hasNext()) {
			Certificate = (TrustCertificate) it_cert.next();

			if(Certificate.getSerial().equals(Serial)&&Certificate.getIssuer().equals(Issuer))
			return Certificate ;
		}
		
		
		return Certificate ;
	}
///////////////////////////////////////////////////////////getuTCert_by_Click/////////////////////////////////////////////////////////////////////////////////////
	public static TrustCertificate getuTCert_by_Click(JTable table)

	{
		String Serial="";
		String Issuer="";		
		int row =table.getSelectedRow();
		if(row==-1) return null;
		Serial=(String)table.getValueAt(row, 0);
		Issuer=(String)table.getValueAt(row, 1);
		
		
		Collection<TrustCertificate> Certs_temp = null;

		try {
			TrustView view = data.Model.openTrustView();
			Certs_temp = view.getUntrustedCertificates();
			view.close();

		} catch (Exception e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
			return null;
		}
	
		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate Certificate=null;

		while (it_cert.hasNext()) {
			Certificate = (TrustCertificate) it_cert.next();

			if(Certificate.getSerial().equals(Serial)&&Certificate.getIssuer().equals(Issuer))
			return Certificate ;
		}
		
		
		return Certificate ;
	}

	// /////////////////////////////////////////////////////////getAss_by_Click/////////////////////////////////////////////////////////////////////////////////////
	public static TrustAssessment getAss_by_Click(JTable table)

	{
		String k = "";
		String ca = "";
		int row = table.getSelectedRow();
		if (row == -1)
			return null;
		k = (String) table.getValueAt(row, 0);
		ca = (String) table.getValueAt(row, 1);

		TrustAssessment Ass_temp = null;

		try {
			TrustView view = data.Model.openTrustView();
			Ass_temp = view.getAssessment(k, ca);
			view.close();

		} catch (Exception e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
			return null;
		}

		return Ass_temp;
	}
	
	
	public static <T> void set_Configuration(String key, T value)
	{
		Configuration conf;
		try {
			conf = data.Model.openConfiguration();
			
			conf.set(key,value);
		
			conf.close();


		} catch (Exception e) {
			JOptionPane
					.showConfirmDialog(
							null,
							"Error reading or concurrent modifying the database! Please restart the application ",
							"Error", JOptionPane.DEFAULT_OPTION);
			e.printStackTrace();
		}
	}
	
	
	public static <T> T get_Configuration(String key, Class<T> type)
	{
		Configuration conf; T type_temp=null;
	try {
		conf = data.Model.openConfiguration();

		
		type_temp=conf.get(key, type );
		
		conf.close();
		


	} catch (Exception e) {
		JOptionPane
				.showConfirmDialog(
						null,
						"Error reading or concurrent modifying the database! Please restart the application ",
						"Error", JOptionPane.DEFAULT_OPTION);
		e.printStackTrace();
	}
		return type_temp;
		
	}
	
	public static void msg(String msg) {
		JOptionPane.showConfirmDialog(null, msg, "Error",
				JOptionPane.DEFAULT_OPTION);
	}
	
	public static void msg(String msg,String type) {
		JOptionPane.showConfirmDialog(null, msg, type,
				JOptionPane.DEFAULT_OPTION);
	}
}