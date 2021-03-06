/*
 * This file is part of the CA Trust Management System (CA-TMS)
 *
 * Copyright 2015 by CA-TMS Team.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package presentation.ui;

import java.awt.Component;
import java.awt.Toolkit;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
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
 * @author Haixin Cai
 */
public class GUILogic {

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
			private boolean exceptionOccurred = false;

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
					publish(e);
				}
				return null;
			}

			@Override
			public void done() {
				if (isCancelled())
					msg("Bootstrapping was aborted before it has been finished.", "Aborted");
				else if (!exceptionOccurred)
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
					else if (chunk instanceof ModelAccessException) {
						msg("Error reading or concurrent modifying the database!");
						exceptionOccurred = true;
					}
					else if (chunk instanceof UnsupportedOperationException) {
						msg("The selected file cannot be used to bootstrap the trust view!");
						exceptionOccurred = true;
					}

				if (progressMonitor.isCanceled())
					cancel(false);
			}
		};

		task.execute();
	}

	/**
	 * @return the issuer string representation for the given certificate
	 * @param certificate
	 */
	public static String getIssuerString(TrustCertificate certificate) {
		if (certificate.getCertificate() instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) certificate.getCertificate();
			return x509cert.getIssuerX500Principal().toString();
		}
		return certificate.getIssuer();
	}

	/**
	 * @return the subject string representation for the given certificate
	 * @param certificate
	 */
	public static String getSubjectString(TrustCertificate certificate) {
		if (certificate.getCertificate() instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) certificate.getCertificate();
			return x509cert.getSubjectX500Principal().toString();
		}
		return certificate.getSubject();
	}

	/**
	 * @return the public key string representation for the given certificate
	 * @param certificate
	 */
	public static String getPublicKeyString(TrustCertificate certificate) {
		if (certificate.getCertificate() instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) certificate.getCertificate();

			if (x509cert.getPublicKey() instanceof RSAPublicKey) {
				RSAPublicKey key = (RSAPublicKey) x509cert.getPublicKey();
				return "[" + x509cert.getPublicKey().getAlgorithm() + "] " +
						key.getModulus().bitCount() + " bits, " +
						"modulus: " + key.getModulus().toString(16) + ", " +
						"public exponent: " + key.getPublicExponent().toString(16);
			}

			if (x509cert.getPublicKey() instanceof DSAPublicKey) {
				DSAPublicKey key = (DSAPublicKey) x509cert.getPublicKey();
				return "[" + x509cert.getPublicKey().getAlgorithm() + "] " +
						"parameters: " + key.getParams() + ", " +
						"y: " + key.getY().toString(16);
			}

			if (x509cert.getPublicKey() instanceof ECPublicKey) {
				ECPublicKey key = (ECPublicKey) x509cert.getPublicKey();
				return "[" + x509cert.getPublicKey().getAlgorithm() + "] " +
						"public x coord: " + key.getW().getAffineX().toString(16) + ", " +
						"public y coord: " + key.getW().getAffineY().toString(16) + ", " +
						"parameters: " + key.getParams();
			}

			return "[" + x509cert.getPublicKey().getAlgorithm() + "] " +
					certificate.getPublicKey();
		}

		return certificate.getPublicKey();
	}

	// /////////////////////////////////////////////////////////refresh_TC_Table/////////////////////////////////////////////////////////////////////////////////////

	/**
	 * to refresh the Trust Certificates Table in the GUI
	 */
	@SuppressWarnings("deprecation")
	public static DefaultTableModel refresh_TC_Table() {

		DefaultTableModel model = new DefaultTableModel(new Object[][] {},
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

		try (TrustView view = data.Model.openTrustView()) {
			Certs_temp = view.getTrustedCertificates();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
		}

		if (Certs_temp == null)
			return model;

		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate certificate;

		while (it_cert.hasNext()) {
			certificate = it_cert.next();
			model.addRow(new Object[] {
					certificate.getSerial(),
					getIssuerString(certificate),
					getSubjectString(certificate),
					getPublicKeyString(certificate),
					certificate.getNotBefore().toGMTString(),
					certificate.getNotAfter().toGMTString()
			});
		}

		return model;
	}

	// /////////////////////////////////////////////////////////refresh_uTC_Table/////////////////////////////////////////////////////////////////////////////////////


	/**
	 *
	 * to refresh the unTrust Certificates Table in the GUI
	 */

	@SuppressWarnings("deprecation")
	public static DefaultTableModel refresh_uTC_Table() {
		DefaultTableModel model = new DefaultTableModel(new Object[][] {},
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
		try (TrustView view = data.Model.openTrustView()) {
			Certs_temp = view.getUntrustedCertificates();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
		}

		if (Certs_temp == null)
			return model;

		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate certificate;
		while (it_cert.hasNext()) {
			certificate = it_cert.next();

			model.addRow(new Object[] {
					certificate.getSerial(),
					getIssuerString(certificate),
					getSubjectString(certificate),
					getPublicKeyString(certificate),
					certificate.getNotBefore().toGMTString(),
					certificate.getNotAfter().toGMTString()
			});
		}

		return model;
	}

	// /////////////////////////////////////////////////////////refresh_Ass_Table/////////////////////////////////////////////////////////////////////////////////////


	/**
	 *
	 * to refresh the Trust Assessment Table in the GUI
	 */

	public static DefaultTableModel refresh_Ass_Table() {
		DefaultTableModel model = new DefaultTableModel(
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
		try (TrustView view = data.Model.openTrustView()) {
			Assessments_temp = view.getAssessments();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
		}

		if (Assessments_temp == null)
			return model;

		Iterator<TrustAssessment> it_ass = Assessments_temp.iterator();
		while (it_ass.hasNext()) {
			TrustAssessment assessment = it_ass.next();
			Iterator<TrustCertificate> iterator = assessment.getS().iterator();
			TrustCertificate certificate = iterator.hasNext() ? iterator.next() : null;

			String o_kl = "";
			o_kl += assessment.getO_kl().isSet() ? "("
					+ assessment.getO_kl().get().getT() + ", "
					+ assessment.getO_kl().get().getC() + ", "
					+ assessment.getO_kl().get().getF() + ")" : "unknown";

			String o_it_ca = "(" + assessment.getO_it_ca().getT() + ", "
					+ assessment.getO_it_ca().getC() + ", "
					+ assessment.getO_it_ca().getF() + ")";
			String o_it_ee = "(" + assessment.getO_it_ee().getT() + ", "
					+ assessment.getO_it_ee().getC() + ", "
					+ assessment.getO_it_ee().getF() + ")";

			String ca = certificate != null ?
					getSubjectString(certificate) : assessment.getCa();
			String k = certificate != null ?
					getPublicKeyString(certificate) : assessment.getK();

			model.addRow(new Object[] { k, ca, o_kl, o_it_ca, o_it_ee });

		}
		return model;
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

		try (TrustView view = data.Model.openTrustView()) {
			Certs_temp = view.getTrustedCertificates();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
			return null;
		}

		Iterator<TrustCertificate> it = Certs_temp.iterator();
		while (it.hasNext()) {
			TrustCertificate it_cert = it.next();
			String it_serial = it_cert.getSerial();
			String it_issuer = getIssuerString(it_cert);

			if (it_serial.equals(Serial) && it_issuer.equals(Issuer))
				return it_cert;
		}

		return null;
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

		try (TrustView view = data.Model.openTrustView()) {
			Certs_temp = view.getUntrustedCertificates();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
			return null;
		}

		Iterator<TrustCertificate> it = Certs_temp.iterator();
		while (it.hasNext()) {
			TrustCertificate it_cert = it.next();
			String it_serial = it_cert.getSerial();
			String it_issuer = getIssuerString(it_cert);

			if (it_serial.equals(Serial) && it_issuer.equals(Issuer))
				return it_cert;
		}

		return null;
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

		Collection<TrustAssessment> Certs_temp = null;

		try (TrustView view = data.Model.openTrustView()) {
			Certs_temp = view.getAssessments();

		} catch (ModelAccessException e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.DEFAULT_OPTION);
			e1.printStackTrace();
			return null;
		}

		Iterator<TrustAssessment> it = Certs_temp.iterator();
		while (it.hasNext()) {
			TrustAssessment it_ass = it.next();
			Iterator<TrustCertificate> iterator = it_ass.getS().iterator();
			TrustCertificate certificate = iterator.hasNext() ? iterator.next() : null;

			String it_ca = certificate != null ?
					getSubjectString(certificate) : it_ass.getCa();
			String it_k = certificate != null ?
					getPublicKeyString(certificate) : it_ass.getK();

			if (it_ca.equals(ca) && it_k.equals(k))
				return it_ass;
		}

		return null;
	}

	/**
	 * store a k/v vaule pair for configuration
	 * @param key
	 * @param value
	 */
	public static <T> void set_Configuration(String key, T value) {
		try (Configuration conf = data.Model.openConfiguration()) {
			conf.set(key, value);
			conf.save();

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
		try (Configuration conf = data.Model.openConfiguration()) {
			return conf.get(key, type);

		} catch (ModelAccessException e) {
			JOptionPane
					.showConfirmDialog(
							null,
							"Error reading or concurrent modifying the database! Please restart the application ",
							"Error", JOptionPane.DEFAULT_OPTION);
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * retrieval a k/v vaule pair for configuration
	 * @param key
	 * @param type
	 * @param defaultValue
	 * @return
	 */
	public static <T> T get_Configuration(String key, Class<T> type, T defaultValue) {
		try (Configuration conf = data.Model.openConfiguration()) {
			if (conf.exists(key))
				return conf.get(key, type);

		} catch (ModelAccessException e) {
			JOptionPane
					.showConfirmDialog(
							null,
							"Error reading or concurrent modifying the database! Please restart the application ",
							"Error", JOptionPane.DEFAULT_OPTION);
			e.printStackTrace();

		}
		return defaultValue;

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