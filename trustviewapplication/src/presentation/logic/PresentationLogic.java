package presentation.logic;

import java.awt.Component;
import java.awt.Toolkit;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.ProgressMonitor;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;

import support.BootstrapService;
import support.Service;

import data.Configuration;
import data.ModelAccessException;
import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

/**
 * provide some logical functions for the GUI class
 *
 */
public class PresentationLogic {

	/**
	 * load a X509 certificate into program
	 * @param filepath as a string
	 * @return a X509Certificate instance
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static X509Certificate LoadCert(String filepath)
			throws CertificateException, IOException {
		InputStream inStream;
		X509Certificate Cert = null;

		inStream = new FileInputStream(filepath);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		Cert = (X509Certificate) cf.generateCertificate(inStream);
		inStream.close();
		return Cert;
	}

	/**
	 * Bootstraps the trust view using the given bootstrap file and the given
	 * security level
	 * @param bootstrapBase
	 * @param securityLevel
	 */
	public static void bootstrapTrustView(final File bootstrapBase,
			final double securityLevel, Component dialogParent) {
		final ProgressMonitor progressMonitor = new ProgressMonitor(
				dialogParent,
				"Bootstrapping the trust view using the Firefox browser history",
				"", 0, 1000);

		final SwingWorker<Void, Object> task = new SwingWorker<Void, Object>() {
			@Override
			protected Void doInBackground() throws Exception {
				try {
					Service.getBootstrapService(bootstrapBase).bootstrap(
							securityLevel,
							new BootstrapService.Observer() {
								@Override
								public boolean update(double progress, String item) {
									if (isCancelled())
										return false;

									publish((int)(1000 * progress));
									publish(item);
									return true;
								}
							});
				}
				catch (ModelAccessException | UnsupportedOperationException e) {
					cancel(false);
					publish(e);
				}
				return null;
			}

			@Override
			public void done() {
				if (isCancelled())
					msg("Bootstrapping was aborted before it has been finished.", "Aborted");
				else
					msg("Bootstrapping was completed successfully.", "Success");
				Toolkit.getDefaultToolkit().beep();
				progressMonitor.close();
			}

			@Override
			protected void process(List<Object> chunks) {
				for (Object chunk : chunks)
					if (chunk instanceof Integer)
						progressMonitor.setProgress((int) chunk);
					else if (chunk instanceof String)
						progressMonitor.setNote((String) chunk);
					else if (chunk instanceof ModelAccessException)
						msg("Error reading or concurrent modifying the database!");
					else if (chunk instanceof UnsupportedOperationException)
						msg("The selected file cannot be used to bootstrap the trust view!");

				if (progressMonitor.isCanceled())
					cancel(false);
			}
		};

		task.execute();
	}

	// /////////////////////////////////////////////////////////refresh_TC_Table/////////////////////////////////////////////////////////////////////////////////////

	/**
	 * to refresh the Trust Certificates Table in the GUI
	 */
	@SuppressWarnings("deprecation")
	public static DefaultTableModel refresh_TC_Table() {

		DefaultTableModel Model = new DefaultTableModel(new Object[][] {},
				new String[] { "Serial", "Issuer", "Subject", "PublicKey",
						"NotBefore", "NotAfter" }) {

							private static final long serialVersionUID = 1L;
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] { String.class, String.class,
					String.class, String.class, String.class, String.class };

			@Override
			@SuppressWarnings({ "rawtypes", "unchecked" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}

			boolean[] columnEditables = new boolean[] { false, false, false,
					false, false, false };

			@Override
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		};

		Collection<TrustCertificate> Certs_temp = null;

		try {
			TrustView view = data.Model.openTrustView();
			Certs_temp = view.getTrustedCertificates();
			view.close();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
		}

		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate Certificate;

		while (it_cert.hasNext()) {
			Certificate = it_cert.next();

			Model.addRow(new Object[] { Certificate.getSerial(),
					Certificate.getIssuer(), Certificate.getSubject(),
					Certificate.getPublicKey(),
					Certificate.getNotBefore().toGMTString(),
					Certificate.getNotAfter().toGMTString() });

		}

		return Model;
	}

	// /////////////////////////////////////////////////////////refresh_uTC_Table/////////////////////////////////////////////////////////////////////////////////////


	/**
	 *
	 * to refresh the unTrust Certificates Table in the GUI
	 */

	@SuppressWarnings("deprecation")
	public static DefaultTableModel refresh_uTC_Table() {
		DefaultTableModel Model = new DefaultTableModel(new Object[][] {},
				new String[] { "Serial", "Issuer", "Subject", "PublicKey",
						"NotBefore", "NotAfter" }) {

							private static final long serialVersionUID = 1L;
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] { String.class, String.class,
					String.class, String.class, String.class, String.class };

			@Override
			@SuppressWarnings({ "rawtypes", "unchecked" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}

			boolean[] columnEditables = new boolean[] { false, false, false,
					false, false, false };

			@Override
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		};

		Collection<TrustCertificate> Certs_temp = null;
		try {
			TrustView view = data.Model.openTrustView();
			Certs_temp = view.getUntrustedCertificates();
			view.close();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
		}

		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate Certificate;
		while (it_cert.hasNext()) {
			Certificate = it_cert.next();

			Model.addRow(new Object[] { Certificate.getSerial(),
					Certificate.getIssuer(), Certificate.getSubject(),
					Certificate.getPublicKey(),
					Certificate.getNotBefore().toGMTString(),
					Certificate.getNotAfter().toGMTString() });

		}
		return Model;
	}

	// /////////////////////////////////////////////////////////refresh_Ass_Table/////////////////////////////////////////////////////////////////////////////////////


	/**
	 *
	 * to refresh the Trust Assessment Table in the GUI
	 */

	public static DefaultTableModel refresh_Ass_Table() {
		DefaultTableModel Model = new DefaultTableModel(
				new Object[][] {},
				new String[] { "PublicKey", "CA", "O_kl", "O_it_ca", "O_it_ee" }) {

					private static final long serialVersionUID = 1L;
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] { String.class, String.class,
					String.class, String.class, Object.class };

			@Override
			@SuppressWarnings({ "rawtypes", "unchecked" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}

			boolean[] columnEditables = new boolean[] { false, false, false,
					true, true };

			@Override
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		};

		Collection<TrustAssessment> Assessments_temp = null;
		try {
			TrustView view = data.Model.openTrustView();
			Assessments_temp = view.getAssessments();
			view.close();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
		}

		Iterator<TrustAssessment> it_ass = Assessments_temp.iterator();
		TrustAssessment Assessment;

		while (it_ass.hasNext()) {
			Assessment = it_ass.next();

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

			Model.addRow(new Object[] { Assessment.getK(), Assessment.getCa(),
					o_kl, o_it_ca, o_it_ee });

		}
		return Model;
	}

	// /////////////////////////////////////////////////////////getTCert_by_Click/////////////////////////////////////////////////////////////////////////////////////
	public static TrustCertificate getTCert_by_Click(JTable table)

	{
		String Serial = "";
		String Issuer = "";
		int row = table.getSelectedRow();
		if (row == -1)
			return null;
		Serial = (String) table.getValueAt(row, 0);
		Issuer = (String) table.getValueAt(row, 1);

		Collection<TrustCertificate> Certs_temp = null;

		try {
			TrustView view = data.Model.openTrustView();
			Certs_temp = view.getTrustedCertificates();
			view.close();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
			return null;
		}

		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate Certificate = null;

		while (it_cert.hasNext()) {
			Certificate = it_cert.next();

			if (Certificate.getSerial().equals(Serial)
					&& Certificate.getIssuer().equals(Issuer))
				return Certificate;
		}

		return Certificate;
	}

	// /////////////////////////////////////////////////////////getuTCert_by_Click/////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @param clicked table
	 * @return a TrustCertificate instance that clicked by user
	 */
	public static TrustCertificate getuTCert_by_Click(JTable table)

	{
		String Serial = "";
		String Issuer = "";
		int row = table.getSelectedRow();
		if (row == -1)
			return null;
		Serial = (String) table.getValueAt(row, 0);
		Issuer = (String) table.getValueAt(row, 1);

		Collection<TrustCertificate> Certs_temp = null;

		try {
			TrustView view = data.Model.openTrustView();
			Certs_temp = view.getUntrustedCertificates();
			view.close();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
			return null;
		}

		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate Certificate = null;

		while (it_cert.hasNext()) {
			Certificate = it_cert.next();

			if (Certificate.getSerial().equals(Serial)
					&& Certificate.getIssuer().equals(Issuer))
				return Certificate;
		}

		return Certificate;
	}

	// /////////////////////////////////////////////////////////getAss_by_Click/////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @param clicked table
	 * @return a TrustAssessment instance that clicked by user
	 */
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

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
			return null;
		}

		return Ass_temp;
	}

	/**
	 * store a k/v vaule pair for configuration
	 * @param key
	 * @param value
	 */
	public static <T> void set_Configuration(String key, T value) {
		Configuration conf;
		try {
			conf = data.Model.openConfiguration();

			conf.set(key, value);

			conf.close();

		} catch (ModelAccessException e) {
			JOptionPane
					.showConfirmDialog(
							null,
							"Error reading or concurrent modifying the database! Please restart the application ",
							"Error", JOptionPane.DEFAULT_OPTION);
			e.printStackTrace();
		}
	}

	/**
	 * retrieval a k/v vaule pair for configuration
	 * @param key
	 * @param type
	 * @return
	 */
	public static <T> T get_Configuration(String key, Class<T> type) {
		Configuration conf;
		T type_temp = null;
		try {
			conf = data.Model.openConfiguration();

			type_temp = conf.get(key, type);

			conf.close();

		} catch (ModelAccessException e) {
			JOptionPane
					.showConfirmDialog(
							null,
							"Error reading or concurrent modifying the database! Please restart the application ",
							"Error", JOptionPane.DEFAULT_OPTION);
			e.printStackTrace();

		}
		return type_temp;

	}

	/**
	 * pop up a error message box
	 * @param msg
	 */
	public static void msg(String msg) {
		JOptionPane.showConfirmDialog(null, msg, "Error",
				JOptionPane.DEFAULT_OPTION);
	}

	/**
	 * pop up a "type" message box
	 * @param msg
	 * @param type
	 */
	public static void msg(String msg, String type) {
		JOptionPane.showConfirmDialog(null, msg, type,
				JOptionPane.DEFAULT_OPTION);
	}
}