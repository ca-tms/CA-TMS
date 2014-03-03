package presentation.ui;

import java.awt.EventQueue;

import javax.swing.JFrame;

import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.JTabbedPane;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import javax.swing.JSlider;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.DefaultTableModel;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JComboBox;

import java.awt.event.ItemListener;
import java.awt.event.ItemEvent;
import java.util.Collection;
import java.util.Iterator;

public class GUI {

	private JFrame frame;
	
	private JTable table_TC;
	private JTable table_uTC;
	private JTextField textField;
	private JTable table_Ass;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) throws Exception {
			

		
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GUI window = new GUI();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public GUI() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */

	@SuppressWarnings({ "unchecked", "serial" })
	private void initialize() {

		frame = new JFrame();
		frame.setBounds(100, 100, 800, 800);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane.setBounds(10, 10, 764, 655);
		frame.getContentPane().add(tabbedPane);
		

		JPanel panel_TC = new JPanel();
		tabbedPane.addTab("Trusted Certificates", null, panel_TC, null);
		panel_TC.setLayout(null);

		JScrollPane scrollPane_TC = new JScrollPane();
		scrollPane_TC.setBounds(10, 10, 739, 554);
		panel_TC.add(scrollPane_TC);

		// ///////////////////////////////////////////////////////////////////TrustCertificate_Table////////////////////////////////////////////////////////////


		DefaultTableModel Model_TrustCert_Table = new DefaultTableModel(
				new Object[][] {}, new String[] { "Serial", "Issuer",
						"Subject", "PublicKey" }) {
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] { String.class, String.class,
					String.class, String.class };

			@SuppressWarnings({ "rawtypes" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}

			boolean[] columnEditables = new boolean[] { false, false, false,
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
					"Error", JOptionPane.ERROR_MESSAGE);
			e1.printStackTrace();
		}

		Iterator<TrustCertificate> it_cert = Certs_temp.iterator();
		TrustCertificate Certificate;

		while (it_cert.hasNext()) {
			Certificate = (TrustCertificate) it_cert.next();

			Model_TrustCert_Table.addRow(new Object[] {
					Certificate.getSerial(), Certificate.getIssuer(),
					Certificate.getSubject(), Certificate.getPublicKey() });
			
		}
		// ////////////////////////////////////////////////////////////////to be delete////////////////////////////////////////////////////
		Model_TrustCert_Table.addRow(new String[] {
				"Certificate.getSerial()", "Certificate.getIssuer()",
				"Certificate.getSubject()", "Certificate.getPublicKey()aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
		Model_TrustCert_Table.addRow(new String[] {
				"Certificate.getSerial()", "Certificate.getIssuer()",
				"Certificate.getSubject()", "Certificate.getPublicKey()" });
		Model_TrustCert_Table.addRow(new String[] {
				"Certificate.getSerial()", "Certificate.getIssuer()",
				"Certificate.getSubject()", "Certificate.getPublicKey()" });
		Model_TrustCert_Table.addRow(new String[] {
				"1", "2",
				"3", "4" });
		// ////////////////////////////////////////////////////////////////to be delete////////////////////////////////////////////////////
      
		table_TC =  new JTable(Model_TrustCert_Table);
		table_TC.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
	
		scrollPane_TC.setViewportView(table_TC);

		// ////////////////////////////////////////////////////////////////Popupmenu for TrustCertificate_Table////////////////////////////////////////////////////

		final JPopupMenu PopMenu_TrustCert = new JPopupMenu();
		final JMenuItem Insert_TC = new JMenuItem("Insert");
		final JMenuItem Delete_TC = new JMenuItem("Delete");
		final JMenuItem Set_uTC = new JMenuItem("Untrust");
		final JMenuItem Edit_TC = new JMenuItem("Edit");
		
		PopMenu_TrustCert.add(Insert_TC);
		PopMenu_TrustCert.add(Delete_TC);
		PopMenu_TrustCert.add(Set_uTC);
		PopMenu_TrustCert.add(Edit_TC);

		table_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 3) {

					int row = table_TC.rowAtPoint(arg0.getPoint());
			         if(row>=0)
			        	 table_TC.setRowSelectionInterval(row,row);

					PopMenu_TrustCert.show(arg0.getComponent(), arg0.getX(),
							arg0.getY());
				}
			}
		});

		
		Insert_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1|| arg0.getButton() == 3) {
					
					
						JOptionPane.showConfirmDialog(null,
								"to be done, delete cert ",
								"Error", JOptionPane.ERROR_MESSAGE);
					
				}	
			}}
		);
		
		Delete_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1|| arg0.getButton() == 3) {
					
					
						JOptionPane.showConfirmDialog(null,
								"to be done, delete cert ",
								"Error", JOptionPane.ERROR_MESSAGE);
					
				}	
			}}
		);
	
		Set_uTC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1|| arg0.getButton() == 3) {
					
						
				}	
			}}
		);
				
		
		Edit_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1|| arg0.getButton() == 3) {
					
					
						JOptionPane.showConfirmDialog(null,
								"to be done, delete cert ",
								"Error", JOptionPane.ERROR_MESSAGE);
						
					
				}	
			}}
		);
		
		// ///////////////////////////////////////////////////////////////////TrustCertificate_Table////////////////////////////////////////////////////////////

		JPanel panel_uTC = new JPanel();
		tabbedPane.addTab("unTrusted Certificates", null, panel_uTC, null);
		panel_uTC.setLayout(null);

		JScrollPane scrollPane_uTC = new JScrollPane();
		scrollPane_uTC.setBounds(10, 10, 739, 554);
		panel_uTC.add(scrollPane_uTC);
		// ///////////////////////////////////////////////////////////////////unTrustCertificate_Table////////////////////////////////////////////////////////////
		


		DefaultTableModel Model_unTrustCert_Table = new DefaultTableModel(
				new Object[][] {}, new String[] { "Serial", "Issuer",
						"Subject", "PublicKey" }) {
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] { String.class, String.class,
					String.class, String.class };

			@SuppressWarnings({ "rawtypes" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}

			boolean[] columnEditables = new boolean[] { false, false, false,
					false };

			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		};

		try {
			TrustView view = data.Model.openTrustView();
			Certs_temp = view.getUntrustedCertificates();
			view.close();

		} catch (Exception e1) {
			JOptionPane.showConfirmDialog(null,
					"Error reading or concurrent modifying the database! ",
					"Error", JOptionPane.ERROR_MESSAGE);
			e1.printStackTrace();
		}

		it_cert = Certs_temp.iterator();

		while (it_cert.hasNext()) {
			Certificate = (TrustCertificate) it_cert.next();

			Model_unTrustCert_Table.addRow(new Object[] {
					Certificate.getSerial(), Certificate.getIssuer(),
					Certificate.getSubject(), Certificate.getPublicKey() });

		}

		// ////////////////////////////////////////////////////////////////to be delete////////////////////////////////////////////////////
		Model_unTrustCert_Table.addRow(new String[] {
				"Certificate.getSerial()", "Certificate.getIssuer()",
				"Certificate.getSubject()", "Certificate.getPublicKey()aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
		Model_unTrustCert_Table.addRow(new String[] {
				"Certificate.getSerial()", "Certificate.getIssuer()",
				"Certificate.getSubject()", "Certificate.getPublicKey()" });
		Model_unTrustCert_Table.addRow(new String[] {
				"Certificate.getSerial()", "Certificate.getIssuer()",
				"Certificate.getSubject()", "Certificate.getPublicKey()" });
		Model_unTrustCert_Table.addRow(new String[] {
				"1", "2",
				"3", "4" });
		// ////////////////////////////////////////////////////////////////to be delete////////////////////////////////////////////////////
		table_uTC = new JTable(Model_unTrustCert_Table);
		
		scrollPane_uTC.setViewportView(table_uTC);
		
		
		// ////////////////////////////////////////////////////////////////Popupmenu for unTrustCertificate_Table////////////////////////////////////////////////////

				final JPopupMenu PopMenu_unTrustCert = new JPopupMenu();
				final JMenuItem Insert_uTC = new JMenuItem("Insert");
				final JMenuItem Delete_uTC = new JMenuItem("Delete");
				final JMenuItem Set_TC = new JMenuItem("Trust");
				final JMenuItem Edit_uTC = new JMenuItem("Edit");
				
				PopMenu_unTrustCert.add(Insert_uTC);
				PopMenu_unTrustCert.add(Delete_uTC);
				PopMenu_unTrustCert.add(Set_TC);
				PopMenu_unTrustCert.add(Edit_uTC);

				table_uTC.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 3) {

							int  row = table_uTC.rowAtPoint(arg0.getPoint());
					         if(row>=0)
					        	 table_uTC.setRowSelectionInterval(row,row);

					         PopMenu_unTrustCert.show(arg0.getComponent(), arg0.getX(),
									arg0.getY());
						}
					}
				});

				
				Insert_uTC.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.ERROR_MESSAGE);
							
						}	
					}}
				);
				
				Delete_uTC.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.ERROR_MESSAGE);
							
						}	
					}}
				);
			
				Set_TC.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
								
						}	
					}}
				);
						
				
				Edit_uTC.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.ERROR_MESSAGE);
								
							
						}	
					}}
				);
		// ///////////////////////////////////////////////////////////////////unTrustCertificate_Table////////////////////////////////////////////////////////////
		
		

		JPanel panel_Ass = new JPanel();
		tabbedPane.addTab("Assessments Management", null, panel_Ass, null);
		panel_Ass.setLayout(null);

		JScrollPane scrollPane_Ass = new JScrollPane();
		scrollPane_Ass.setBounds(10, 10, 739, 554);
		panel_Ass.add(scrollPane_Ass);
		// ///////////////////////////////////////////////////////////////////Assessment_Table////////////////////////////////////////////////////////////
		


		DefaultTableModel Model_Assessment = new DefaultTableModel(
				new Object[][] {}, new String[] { "PublicKey", "CA",
						"TrustCertificate", "O_kl", "O_it_ca", "O_it_ee" }) {
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] { String.class, String.class,
					String.class, String.class, String.class, Object.class };

			@SuppressWarnings("rawtypes")
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}

			boolean[] columnEditables = new boolean[] { false, false, false,
					false, false, false };

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
					"Error", JOptionPane.ERROR_MESSAGE);
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

			Model_TrustCert_Table.addRow(new Object[] { Assessment.getK(),
					Assessment.getCa(), S, o_kl, o_it_ca, o_it_ee });

		}
		// ////////////////////////////////////////////////////////////////to be delete////////////////////////////////////////////////////
		Model_Assessment.addRow(new String[] { "Assessment.getK()",
				"Assessment.getCa()", "S"," o_kl", "o_it_ca", "o_it_ee" });
		Model_Assessment.addRow(new String[] { "Assessment.getK()",
				"Assessment.getCa()", "S"," o_kl", "o_it_ca", "o_it_ee" });
		Model_Assessment.addRow(new String[] { "Assessment.getK()",
						"Assessment.getCa()", "S"," o_kl", "o_it_ca", "o_it_ee" });
		Model_Assessment.addRow(new String[] { "Assessment.getK()",
								"Assessment.getCa()", "S"," o_kl", "o_it_ca", "o_it_ee" });
		Model_Assessment.addRow(new String[] { "Assessment.getK()",
										"Assessment.getCa()", "S"," o_kl", "o_it_ca", "o_it_ee111111111111111111111111111111111111111111111111111111111111" });
				// ////////////////////////////////////////////////////////////////to be delete////////////////////////////////////////////////////
		table_Ass = new JTable(Model_Assessment);
		scrollPane_Ass.setViewportView(table_Ass);
		// ////////////////////////////////////////////////////////////////Popupmenu for TrustCertificate_Table////////////////////////////////////////////////////

				final JPopupMenu PopMenu_Ass = new JPopupMenu();
				final JMenuItem Insert_Ass = new JMenuItem("Insert");
				final JMenuItem Delete_Ass = new JMenuItem("Delete");
				final JMenuItem Edit_Ass = new JMenuItem("Edit");
				
				PopMenu_Ass.add(Insert_Ass);
				PopMenu_Ass.add(Delete_Ass);
				PopMenu_Ass.add(Edit_Ass);

				table_Ass.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 3) {

							int row = table_Ass.rowAtPoint(arg0.getPoint());
					         if(row>=0)
					        	 table_Ass.setRowSelectionInterval(row,row);

					         PopMenu_Ass.show(arg0.getComponent(), arg0.getX(),
									arg0.getY());
						}
					}
				});

				
				Insert_Ass.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.ERROR_MESSAGE);
							
						}	
					}}
				);
				
				Delete_Ass.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.ERROR_MESSAGE);
							
						}	
					}}
				);
			
						
				
				Edit_Ass.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.ERROR_MESSAGE);
								
							
						}	
					}}
				);
////////////////////////////////////////////////////////////////////////////configuration pannel//////////////////////////////////////////
		JPanel panel_Conf = new JPanel();
		tabbedPane.addTab("Configuration", null, panel_Conf, null);
		panel_Conf.setLayout(null);

		@SuppressWarnings("rawtypes")
		final JComboBox comboBox = new JComboBox();
		comboBox.setBounds(428, 25, 81, 21);
		panel_Conf.add(comboBox);
		comboBox.addItem("High");
		comboBox.addItem("Medium");
		comboBox.addItem("Low");
		comboBox.addItem("Custom");
		comboBox.setSelectedIndex(1);

		JLabel label_1 = new JLabel("0.95");
		label_1.setBounds(428, 84, 54, 15);
		panel_Conf.add(label_1);

		final JSlider slider = new JSlider();
		slider.setBounds(227, 46, 200, 26);
		panel_Conf.add(slider);
		slider.setValue(80);
		slider.setMaximum(95);
		slider.setMinimum(60);

		JLabel lblSecurityLevel = new JLabel("Security Level :");
		lblSecurityLevel.setBounds(290, 28, 96, 15);
		panel_Conf.add(lblSecurityLevel);

		JLabel label = new JLabel("0.6");
		label.setBounds(227, 84, 54, 15);
		panel_Conf.add(label);

		textField = new JTextField("" + (float) slider.getValue() / 100);
		textField.setEditable(false);
		textField.setBounds(313, 81, 45, 21);
		panel_Conf.add(textField);
		textField.setColumns(10);

		slider.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent event) {
				if ((JSlider) event.getSource() == slider) {
					float val = (float) slider.getValue() / 100;
					String str = "" + val;
					textField.setText(str);
					comboBox.setSelectedIndex(3);
				}
			}
		});
		comboBox.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
					int level = slider.getValue();

					if (comboBox.getSelectedIndex() == 0)
						level = 95;
					else if (comboBox.getSelectedIndex() == 1)
						level = 80;
					else if (comboBox.getSelectedIndex() == 2)
						level = 60;

					float val = (float) level / 100;
					String str = "" + val;
					textField.setText(str);
					slider.setValue(level);
				}
			}
		});

		JPanel panel_About = new JPanel();
		tabbedPane.addTab("About", null, panel_About, null);

		JToggleButton tglbtnStartService = new JToggleButton("Service On/Off");
		tglbtnStartService.setBounds(28, 709, 135, 23);
		frame.getContentPane().add(tglbtnStartService);

		JButton btnMiniminze = new JButton("Miniminze");
		btnMiniminze.setBounds(513, 709, 93, 23);
		btnMiniminze.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				frame.setExtendedState(JFrame.ICONIFIED);
			}
		});
		frame.getContentPane().add(btnMiniminze);

		JButton btnClose = new JButton("Close");
		btnClose.setBounds(653, 709, 93, 23);
		btnClose.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {
				System.exit(0);
			}
		});
		frame.getContentPane().add(btnClose);

	}
}
