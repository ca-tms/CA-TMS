package presentation.ui;

import java.awt.EventQueue;

import javax.swing.JFrame;



import java.io.*;
import java.util.*;

import data.Configuration;
import data.Model;
import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

import javax.swing.BorderFactory;
import javax.swing.JFileChooser;
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
import javax.swing.UIManager;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import CertainTrust.CertainTrust;
import presentation.logic.PresentationLogic;
import services.bindings.WebServer;



















import util.Util;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.awt.Font;

import javax.swing.border.TitledBorder;
import javax.swing.JTextPane;

public class GUI {

	private JFrame frame;
	
	private JTable table_TC;
	private JTable table_uTC;
	private JTable table_Ass;
	
	private int[] PreferredWidth_TC ={120,145,145,123,102,102};
	private int[] PreferredWidth_uTC ={120,145,145,123,102,102};
	private int[] PreferredWidth_Ass ={122,157,157,123,89,89};
	TableColumn[] Trust_Cert_TableCol= new TableColumn[6];
	TableColumn[] UnTrust_Cert_TableCol= new TableColumn[6];
	TableColumn[] Ass_TableCol= new TableColumn[6];
	
	private JTextField textField_high;
	private JTextField textField_med;
	private JTextField textField_low;
	
	private TrustView view;
	
	private float security_level_low;
	private float security_level_med;
	private float security_level_high;
	
	private long assessment_expiration_millis;

	private int Port;
	private JTextField textField_Expiration;
	private JTextField textField_Port;

	int port;
	WebServer server;

	
	
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
		Configurate();
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */

	public void Configurate()
	{ 
			
		
			assessment_expiration_millis=PresentationLogic.get_Configuration(Configuration.ASSESSMENT_EXPIRATION_MILLIS, Long.class);
			
			 Port=PresentationLogic.get_Configuration(Configuration.SERVER_PORT, Integer.class);
			
			security_level_low=PresentationLogic.get_Configuration(Configuration.SECURITY_LEVEL_LOW, Float.class);
			security_level_med=PresentationLogic.get_Configuration(Configuration.SECURITY_LEVEL_MEDIUM, Float.class);
			security_level_high=PresentationLogic.get_Configuration(Configuration.SECURITY_LEVEL_HIGH, Float.class);
		
	 
	}
	
	
	private void initialize() {

		try {
			UIManager
					.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
		} catch (Exception e) {
		}

		frame = new JFrame();
		frame.setResizable(true);
		frame.setBounds(100, 100, 610, 621);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane.setBounds(10, 10, 574, 497);
		frame.getContentPane().add(tabbedPane);

		JPanel panel_TC = new JPanel();
		tabbedPane.addTab("Trusted Certificates", null, panel_TC, null);
		panel_TC.setLayout(null);

		JScrollPane scrollPane_TC = new JScrollPane();
		scrollPane_TC.setBounds(10, 10, 549, 448);
		panel_TC.add(scrollPane_TC);

		// ///////////////////////////////////////////////////////////////////TrustCertificate_Table////////////////////////////////////////////////////////////

		table_TC = new JTable(PresentationLogic.refresh_TC_Table());

		table_TC.setFont(new Font("Arial", Font.PLAIN, 14));
		table_TC.setRowHeight(25);
		table_TC.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		refresh_ColWidth();

		scrollPane_TC.setViewportView(table_TC);

		// ////////////////////////////////////////////////////////////////Popupmenu
		// for
		// TrustCertificate_Table////////////////////////////////////////////////////

		final JPopupMenu PopMenu_TrustCert = new JPopupMenu();
		final JMenuItem Insert_TC = new JMenuItem("Insert");
		final JMenuItem Delete_TC = new JMenuItem("Delete");
		final JMenuItem Set_uTC = new JMenuItem("Set untrust");

		PopMenu_TrustCert.add(Insert_TC);
		PopMenu_TrustCert.add(Delete_TC);
		PopMenu_TrustCert.add(Set_uTC);

		// /////////////////////////////////////////////////////////////////////////////////////Listener////////////////////////////////////////////////////
		scrollPane_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 3) {

					int row = table_TC.rowAtPoint(arg0.getPoint());
					if (row >= 0)
						table_TC.setRowSelectionInterval(row, row);

					PopMenu_TrustCert.show(arg0.getComponent(), arg0.getX(),
							arg0.getY());
				}
			}
		});

		table_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 3) {

					int row = table_TC.rowAtPoint(arg0.getPoint());
					if (row >= 0)
						table_TC.setRowSelectionInterval(row, row);

					PopMenu_TrustCert.show(arg0.getComponent(), arg0.getX(),
							arg0.getY());
				}
			}
		});

		// /////////////////////////////////////////////////////////////////////////Insert menu//////////////////////////////////
		Insert_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					String Cert_Path = "";
					JFileChooser Cert_Chooser = new JFileChooser();

					FileFilter Cert_filter = new FileNameExtensionFilter(
							"X.509 Certificate", "cer");
					Cert_Chooser.setFileFilter(Cert_filter);
					int returnVal = Cert_Chooser.showOpenDialog(table_TC);

					if (returnVal == JFileChooser.APPROVE_OPTION) {

						Cert_Path = Cert_Chooser.getSelectedFile()
								.getAbsolutePath();
					}
						if(!new File(Cert_Path).exists())
					{PresentationLogic.msg("File not found!");
					return;
					}

					try {
						X509Certificate cert = PresentationLogic
								.LoadCert(Cert_Path);
						TrustView view = data.Model.openTrustView();
						view.setTrustedCertificate(new TrustCertificate(cert));
						view.close();

						table_TC.setModel(PresentationLogic.refresh_TC_Table());
						table_uTC.setModel(PresentationLogic.refresh_uTC_Table());
						refresh_ColWidth();

					} catch (CertificateException e) {
						PresentationLogic.msg("Cannot create a TrustCertificate from not X.509 Certificate ");
						e.printStackTrace();
					} catch (IOException e) {
						if (Cert_Path.equals(""))
							return;
						else
							PresentationLogic.msg("Error reading Certificate File ");
							
						e.printStackTrace();
					} catch (Exception e) {
						PresentationLogic.msg("Error reading or concurrent modifying the database! ");
		
						e.printStackTrace();
					}

				}
			}
		});
		// ////////////////////////////////////////////////////////////Delete//////////////////////////////////////////////////////////
		Delete_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {
					
					TrustCertificate Cert = PresentationLogic
							.getTCert_by_Click(table_TC);
					if (Cert == null)
						return;

					try {
						view = data.Model.openTrustView();
						view.removeCertificate(Cert);
						view.close();

						table_TC.setModel(PresentationLogic.refresh_TC_Table());
						refresh_ColWidth();

					} catch (Exception e) {
						
						PresentationLogic.msg("Error reading or concurrent modifying the database! ");
						
						e.printStackTrace();
					}
					

				}
			}
		});
		// ////////////////////////////////////////////////////////////Set untrust////////////////////////////////////////////////////
		Set_uTC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					TrustCertificate uTCertificate = PresentationLogic
							.getTCert_by_Click(table_TC);
					if (uTCertificate == null)
						return;
					
					try {
						view = data.Model.openTrustView();
						view.setUntrustedCertificate(uTCertificate);
						view.close();

						table_TC.setModel(PresentationLogic.refresh_TC_Table());
						table_uTC.setModel(PresentationLogic
								.refresh_uTC_Table());
						refresh_ColWidth();

					} catch (Exception e) {
						
						PresentationLogic.msg("Error reading or concurrent modifying the database! ");
						
						e.printStackTrace();
					}

				}
			}
		});

		// ///////////////////////////////////////////////////////////////////unTrustCertificate_panel///////////////////////////////////////////

		JPanel panel_uTC = new JPanel();
		tabbedPane.addTab("unTrusted Certificates", null, panel_uTC, null);
		panel_uTC.setLayout(null);

		JScrollPane scrollPane_uTC = new JScrollPane();
		scrollPane_uTC.setBounds(10, 10, 549, 448);
		panel_uTC.add(scrollPane_uTC);
		// ///////////////////////////////////////////////////////////////////unTrustCertificate_Table////////////////////////////////////

		table_uTC = new JTable(PresentationLogic.refresh_uTC_Table());
		table_uTC.setFont(new Font("Arial", Font.PLAIN, 14));
		table_uTC.setRowHeight(25);
		table_uTC.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		refresh_ColWidth();
		scrollPane_uTC.setViewportView(table_uTC);

		// /////////////////////////////////////////////////Popupmenu for unTrustCertificate_Table////////////////////////////

		final JPopupMenu PopMenu_unTrustCert = new JPopupMenu();
		final JMenuItem Insert_uTC = new JMenuItem("Insert");
		final JMenuItem Delete_uTC = new JMenuItem("Delete");
		final JMenuItem Set_TC = new JMenuItem("Set trust");

		PopMenu_unTrustCert.add(Insert_uTC);
		PopMenu_unTrustCert.add(Delete_uTC);
		PopMenu_unTrustCert.add(Set_TC);

		// //////////////////////////////////////////////////////////////////Listener for POPUP////////////////////////////////////////////////////

		table_uTC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 3) {

					int row = table_uTC.rowAtPoint(arg0.getPoint());
					if (row >= 0)
						table_uTC.setRowSelectionInterval(row, row);

					PopMenu_unTrustCert.show(arg0.getComponent(), arg0.getX(),
							arg0.getY());
				}
			}
		});
		scrollPane_uTC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 3) {

					int row = table_uTC.rowAtPoint(arg0.getPoint());
					if (row >= 0)
						table_uTC.setRowSelectionInterval(row, row);

					PopMenu_unTrustCert.show(arg0.getComponent(), arg0.getX(),
							arg0.getY());
				}
			}
		});

		// //////////////////////////////////////////////////Insertfor unTrustCertificate//////////////////////////////////////////////////////
		Insert_uTC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					String Cert_Path = "";
					JFileChooser Cert_Chooser = new JFileChooser();

					FileFilter Cert_filter = new FileNameExtensionFilter(
							"X.509 Certificate", "cer");
					Cert_Chooser.setFileFilter(Cert_filter);
					int returnVal = Cert_Chooser.showOpenDialog(table_uTC);

					if (returnVal == JFileChooser.APPROVE_OPTION) {

						Cert_Path = Cert_Chooser.getSelectedFile()
								.getAbsolutePath();
					}
					
					if(!new File(Cert_Path).exists())
					{PresentationLogic.msg("File not found!");
					return; 
					}

					try {
						X509Certificate cert = PresentationLogic
								.LoadCert(Cert_Path);
						TrustView view = data.Model.openTrustView();
						view.setUntrustedCertificate(new TrustCertificate(cert));
						view.close();

						table_uTC.setModel(PresentationLogic
								.refresh_uTC_Table());
						table_TC.setModel(PresentationLogic.refresh_TC_Table());
						refresh_ColWidth();

					} catch (CertificateException e) {
						PresentationLogic.msg("Cannot create a TrustCertificate from not X.509 Certificate ");
						
						e.printStackTrace();
					} catch (IOException e) {
						if (Cert_Path.equals(""))
							return;
						else
							PresentationLogic.msg("Error reading Certificate File ");
						
						e.printStackTrace();
					} catch (Exception e) {
						PresentationLogic.msg("Error reading or concurrent modifying the database! ");
					
						e.printStackTrace();
					}

				}
			}
		});
		// /////////////////////////////////////////////////////////////////Delete_uTC/////////////////////////////////////////////////////////////
		Delete_uTC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					TrustCertificate Cert = PresentationLogic
							.getuTCert_by_Click(table_uTC);
					if (Cert == null)
						{System.out.print("sb");
						return;}

					try {
						view = data.Model.openTrustView();
						view.removeCertificate(Cert);
						view.close();
						

						table_uTC.setModel(PresentationLogic.refresh_uTC_Table());
						refresh_ColWidth();

					} catch (Exception e) {
						
						PresentationLogic.msg("Error reading or concurrent modifying the database! ");
						
						e.printStackTrace();
					}

				}
			}
		});

		// /////////////////////////////////////////////////////////////////Set_TC/////////////////////////////////////////////////////////////
		Set_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					TrustCertificate TCertificate = PresentationLogic
							.getuTCert_by_Click(table_uTC);

					if (TCertificate == null)
						return;

				
					try {
						view = data.Model.openTrustView();
						view.setTrustedCertificate(TCertificate);
						view.close();

						table_TC.setModel(PresentationLogic.refresh_TC_Table());
						table_uTC.setModel(PresentationLogic
								.refresh_uTC_Table());
						refresh_ColWidth();

					} catch (Exception e) {
						PresentationLogic.msg("Error reading or concurrent modifying the database! ");
						
						e.printStackTrace();
					}

				}
			}
		});

		// ///////////////////////////////////////////////////////////////////panel_Ass/////////////////////////////////////////////

		JPanel panel_Ass = new JPanel();
		tabbedPane.addTab("Assessments Management", null, panel_Ass, null);
		panel_Ass.setLayout(null);

		JScrollPane scrollPane_Ass = new JScrollPane();
		scrollPane_Ass.setBounds(10, 10, 549, 448);
		panel_Ass.add(scrollPane_Ass);
		// ///////////////////////////////////////////////////////////////////Assessment_Table///////////////////////////////////

		table_Ass = new JTable(PresentationLogic.refresh_Ass_Table());
		table_Ass.setFont(new Font("Arial", Font.PLAIN, 14));
		table_Ass.setRowHeight(25);
		table_Ass.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		refresh_ColWidth();
		scrollPane_Ass.setViewportView(table_Ass);
		// //////////////////////////////////////////////Popupmenufor ASS//////////////////////////////////////////////////////////

		final JPopupMenu PopMenu_Ass = new JPopupMenu();
		final JMenuItem Delete_Ass = new JMenuItem("Delete");
		final JMenuItem Edit_Ass = new JMenuItem("Edit");
		final JMenuItem Set_Valid_Ass = new JMenuItem("Set Valid");
		final JMenuItem Clean_Ass = new JMenuItem("Clean Assessments");

		PopMenu_Ass.add(Edit_Ass);
		PopMenu_Ass.add(Delete_Ass);
		PopMenu_Ass.add(Set_Valid_Ass);
		PopMenu_Ass.add(Clean_Ass);
		// /////////////////////////////////////////////\////////////////////Listener for Ass//////////////////////////////////////////////////
		table_Ass.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 3) {

					int row = table_Ass.rowAtPoint(arg0.getPoint());
					if (row >= 0)
						table_Ass.setRowSelectionInterval(row, row);

					PopMenu_Ass.show(arg0.getComponent(), arg0.getX(),
							arg0.getY());
				}
			}
		});

		scrollPane_Ass.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 3) {

					int row = table_Ass.rowAtPoint(arg0.getPoint());
					if (row >= 0)
						table_Ass.setRowSelectionInterval(row, row);

					PopMenu_Ass.show(arg0.getComponent(), arg0.getX(),
							arg0.getY());
				}
			}
		});

		// /////////////////////////////////////////////////////Delete_Ass/////////////////////////////////////////////////////////////

		Delete_Ass.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					 TrustAssessment Ass = PresentationLogic
							.getAss_by_Click(table_Ass);
					if (Ass == null)
						return;

					try {
						view = data.Model.openTrustView();
						view.removeAssessment(Ass.getK(), Ass.getCa());
						view.close();

						table_Ass.setModel(PresentationLogic.refresh_Ass_Table());
						refresh_ColWidth();

					} catch (Exception e) {
						
						PresentationLogic.msg("Error reading or concurrent modifying the database! ");
						
						e.printStackTrace();
					}


				}
			}
		});

		// //////////////////////////////////////////////////////////Edit_Ass/////////////////////////////////////////////////////
		Edit_Ass.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					table_Ass.editCellAt(table_Ass.getSelectedRow(), 4);

				}
			}
		});
	///////////////////////////////////////////////////////////////////Set_Valid_Ass/////////////////////////////////////////////////
		Set_Valid_Ass.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					String k = "";
					String ca = "";
					int row = table_Ass.getSelectedRow();
					if (row == -1)
						return;
					k = (String) table_Ass.getValueAt(row, 0);
					ca = (String) table_Ass.getValueAt(row, 1);

					 
					try {
						view = data.Model.openTrustView();
						view.setAssessmentValid(k, ca);
						view.close();
					} catch (Exception e) {
						PresentationLogic.msg("Error reading or concurrent modifying the database! ");
					
					}

				}
			}
		});
		// ////////////////////////////////////////////////////////////////////////Clean_Ass//////////////////////////////////////////////////////
		Clean_Ass.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {
					 
					try {
						view = data.Model.openTrustView();
						view.clean();
						view.close();
					} catch (Exception e) {
						PresentationLogic.msg("Error reading or concurrent modifying the database! ");
						
						e.printStackTrace();
					}

					table_Ass.setModel(PresentationLogic.refresh_Ass_Table());
					refresh_ColWidth();
				}
			}
		});
		// //////////////////////////////////////////////////////////////////////////configuration pannel///////////////////////////////////////////////
		final JPanel panel_Conf = new JPanel();
		tabbedPane.addTab("Configuration", null, panel_Conf, null);
		panel_Conf.setLayout(null);

		JPanel Outer_Security_Level = new JPanel();
		Outer_Security_Level.setBounds(10, 10, 549, 123);
		Outer_Security_Level.setBorder(BorderFactory
				.createTitledBorder("Security Level Setting"));
		Outer_Security_Level.setLayout(null);
		panel_Conf.add(Outer_Security_Level);
/////////////////////////////////////////////////////////////Security level setting panel/////////////////////////////////////////////////////
		final JSlider slider_high = new JSlider();
		slider_high.setValue((int)(security_level_high*100));
		slider_high.setBounds(30, 24, 143, 26);
		Outer_Security_Level.add(slider_high);

		final JSlider slider_med = new JSlider();
		slider_med.setBounds(203, 24, 143, 26);
		slider_med.setValue((int)(security_level_med*100));
		Outer_Security_Level.add(slider_med);

		final JSlider slider_low = new JSlider();
		slider_low.setBounds(376, 24, 143, 26);
		slider_low.setValue((int)(security_level_low*100));
		Outer_Security_Level.add(slider_low);

		JLabel label_min_high = new JLabel("0.0");
		label_min_high.setBounds(20, 49, 30, 15);
		Outer_Security_Level.add(label_min_high);

		JLabel label_max_high = new JLabel("1.0");
		label_max_high.setBounds(153, 49, 30, 15);
		Outer_Security_Level.add(label_max_high);

		textField_high = new JTextField("" + (float) slider_high.getValue() / 100);
		textField_high.setBounds(97, 72, 37, 21);
		textField_high.setEditable(false);
		Outer_Security_Level.add(textField_high);

		JLabel label_min_med = new JLabel("0.0");
		label_min_med.setBounds(193, 49, 30, 15);
		Outer_Security_Level.add(label_min_med);

		textField_low = new JTextField("" + (float) slider_low.getValue() / 100);
		textField_low.setBounds(451, 72, 37, 21);
		textField_low.setEditable(false);
		Outer_Security_Level.add(textField_low);

		JLabel label_max_med = new JLabel("1.0");
		label_max_med.setBounds(326, 49, 30, 15);
		Outer_Security_Level.add(label_max_med);

		JLabel label__min_low = new JLabel("0.0");
		label__min_low.setBounds(366, 49, 30, 15);
		Outer_Security_Level.add(label__min_low);

		textField_med = new JTextField("" + (float) slider_med.getValue() / 100);
		textField_med.setBounds(273, 72, 37, 21);
		textField_med.setEditable(false);
		Outer_Security_Level.add(textField_med);

		JLabel label_max_low = new JLabel("1.0");
		label_max_low.setBounds(499, 49, 30, 15);
		Outer_Security_Level.add(label_max_low);

		JLabel lblHigh = new JLabel("High:");
		lblHigh.setBounds(61, 74, 37, 15);
		Outer_Security_Level.add(lblHigh);

		JLabel lblMedium = new JLabel("Medium:");
		lblMedium.setBounds(225, 75, 54, 15);
		Outer_Security_Level.add(lblMedium);

		JLabel lblLow = new JLabel("Low:");
		lblLow.setBounds(419, 75, 54, 15);
		Outer_Security_Level.add(lblLow);
		
		JPanel Outer_General_Setting = new JPanel();
		Outer_General_Setting.setBorder(new TitledBorder(null, "General Setting", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		Outer_General_Setting.setBounds(10, 143, 549, 224);
		panel_Conf.add(Outer_General_Setting);
		Outer_General_Setting.setLayout(null);
		
		JLabel lblNewLabel_1 = new JLabel("Assessment Expiration (in Milliseconds):");
		lblNewLabel_1.setBounds(10, 29, 258, 15);
		Outer_General_Setting.add(lblNewLabel_1);
		
		textField_Expiration = new JTextField();
		textField_Expiration.setBounds(264, 26, 172, 21);
		textField_Expiration.setText(""+assessment_expiration_millis);
		Outer_General_Setting.add(textField_Expiration);
		textField_Expiration.setColumns(10);
		
		JButton btnApply = new JButton("Apply");

		btnApply.setBounds(446, 25, 93, 23);
		Outer_General_Setting.add(btnApply);
		
		JLabel lblBindingPortFor = new JLabel("Binding Port for Trust Service:");
		lblBindingPortFor.setBounds(139, 70, 204, 15);
		Outer_General_Setting.add(lblBindingPortFor);
		
		textField_Port = new JTextField();
		textField_Port.setBounds(370, 67, 66, 21);
		textField_Port.setText(""+Port);
		Outer_General_Setting.add(textField_Port);
		textField_Port.setColumns(10);
		
		JButton btnChange = new JButton("Change");
	
		btnChange.setBounds(446, 66, 93, 23);
		Outer_General_Setting.add(btnChange);
		
		JPanel Outer_Data_Backup = new JPanel();
		Outer_Data_Backup.setBorder(new TitledBorder(null, "Data Backup", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		Outer_Data_Backup.setBounds(10, 376, 549, 72);
		panel_Conf.add(Outer_Data_Backup);
		Outer_Data_Backup.setLayout(null);
		
		JButton btnImport = new JButton("Import");
		
		btnImport.setBounds(102, 31, 93, 23);
		Outer_Data_Backup.add(btnImport);
		
		JButton btnExport = new JButton("Export");

		btnExport.setBounds(340, 31, 93, 23);
		Outer_Data_Backup.add(btnExport);
///////////////////////////////////////////////////////////////////////////////////Security level setting listner//////////////////////////////////////////////////////////////////////////////
		slider_high.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent event) {
				if ((JSlider) event.getSource() == slider_high) {
					float val = (float) slider_high.getValue() / 100;
					String str = "" + val;
					textField_high.setText(str);
					
					if(!slider_high.getValueIsAdjusting())
					{
						if(slider_high.getValue()<=slider_med.getValue())
						{
							PresentationLogic.msg("Please select a correct value(not smaller than medium level)! ");
							
							slider_high.setValue((int)(security_level_high*100));
	
						}
						else
						{
						
							security_level_high=(float)slider_high.getValue()/100;
							PresentationLogic.set_Configuration(Configuration.SECURITY_LEVEL_HIGH,security_level_high );
							
							
						}
					}
				}
			}
		});
		
		slider_med.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent event) {
				if ((JSlider) event.getSource() == slider_med) {
					float val = (float) slider_med.getValue() / 100;
					String str = "" + val;
					textField_med.setText(str);

					if(!slider_med.getValueIsAdjusting())
					{
						if(slider_med.getValue()>=slider_high.getValue()||slider_med.getValue()<=slider_low.getValue())
						{
							PresentationLogic.msg("Please select a correct value(not bigger than high level and not smaller than low level)! ");
						
							slider_med.setValue((int)(security_level_med*100));
	
						}
						else
						{
						
							security_level_med=(float)slider_med.getValue()/100;
							PresentationLogic.set_Configuration(Configuration.SECURITY_LEVEL_MEDIUM,security_level_med );
							
							
						}
					}
					
				}
			}
		});
		
		slider_low.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent event) {
				if ((JSlider) event.getSource() == slider_low) {
					float val = (float) slider_low.getValue() / 100;
					String str = "" + val;
					textField_low.setText(str);
					
					if(!slider_low.getValueIsAdjusting())
					{
						if(slider_med.getValue()<=slider_low.getValue())
						{
							PresentationLogic.msg("Please select a correct value(not bigger medium level)! ");
						
							slider_low.setValue((int)(security_level_low*100));
	
						}
						else
						{
						
							security_level_low=(float)slider_low.getValue()/100;
							PresentationLogic.set_Configuration(Configuration.SECURITY_LEVEL_LOW,security_level_low );
							
							
						}
					}

				}
			}
		});

////////////////////////////////////////////////////////////////////////////////Backup listner/////////////////////////////////////////////////////
		
		
		btnImport.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {
				String Import_Path = "";
				JFileChooser Import_Chooser = new JFileChooser();
				Import_Chooser.setFileSelectionMode( JFileChooser.OPEN_DIALOG );
				Import_Chooser.setDialogTitle("Import Backup File"); 
				FileFilter Import_filter = new FileNameExtensionFilter(
						"Trust Service Backup File(.bak)", "bak");
				Import_Chooser.setDialogType(JFileChooser.OPEN_DIALOG);
				Import_Chooser.setApproveButtonText("Open");
				Import_Chooser.setFileFilter(Import_filter);
				
			
				int returnVal = Import_Chooser.showOpenDialog(panel_Conf);

				if (returnVal == JFileChooser.APPROVE_OPTION) {

					Import_Path = Import_Chooser.getSelectedFile()
							.getAbsolutePath();
				}
				
				if(!new File(Import_Path).exists())
				{
					PresentationLogic
					.msg("Import Backup File not exist !");
				return;}
				

				try {
					
					Model.restore(new File(Import_Path));
					
				} catch (Exception e) {
					PresentationLogic
					.msg("Importing Backup File Error !");
					e.printStackTrace();
					return;
				}
				
				table_TC.setModel(PresentationLogic.refresh_TC_Table());
				table_uTC.setModel(PresentationLogic
						.refresh_uTC_Table());
				table_Ass.setModel(PresentationLogic
						.refresh_Ass_Table());
				
				refresh_ColWidth();
				
       
				PresentationLogic
				.msg("Success Importing Backup File !","Success");
			}
		});
		btnExport.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {
				if (arg0.getButton() == 1) {

					String Export_Path = "";
					File Export_File;
					
					JFileChooser Export_Chooser = new JFileChooser();
					Export_Chooser.setDialogTitle("Save Backup File");  
					Export_Chooser.setFileSelectionMode( JFileChooser.APPROVE_OPTION  );
					Export_Chooser.setDialogType(JFileChooser.SAVE_DIALOG);
					Export_Chooser.setApproveButtonText("Save");
					FileFilter Export_filter= new FileNameExtensionFilter(
							"Trust Service Backup File(.bak)", "bak");
					Export_Chooser.setFileFilter(Export_filter);
					
					
					int returnVal = Export_Chooser.showSaveDialog(panel_Conf);

					if (returnVal == JFileChooser.APPROVE_OPTION) {

						Export_Path = Export_Chooser.getSelectedFile()
								.getAbsolutePath();
					}
					
					Export_File=new File(Export_Path);
					
					if(!Export_Path.endsWith(".bak"))
						Export_Path=Export_Path+".bak";
					
					if(Export_File.exists())
					{
						int n = JOptionPane.showConfirmDialog(null, "Are you sure to overwrite file "+new File(Export_Path).getName()+" with the new backup file ?", "Are you Sure ?", JOptionPane.YES_NO_OPTION); 
						if(n == JOptionPane.NO_OPTION)
						return;
					}
					
					if(!Export_Path.equals(".bak"))
						{try {
							
							Model.backup(Export_File);
							
						} catch (Exception e) {
							PresentationLogic
							.msg("Exporting Backup File Error !");
							e.printStackTrace();
							return;
						}
						
						PresentationLogic
						.msg("Success Exporting Backup File !","Success");
						
					}
					}
					
					
					
			}
			}
		);
		
///////////////////////////////////////////////////////////////////////////////////General setting setting//////////////////////////////////////////////////////////////////////////////
		btnChange.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {
				int get_port = Integer.valueOf(textField_Port.getText());
				if (get_port < 200 || get_port > 65535) {
					PresentationLogic
							.msg("Please enter a valid Port Number(200 < Number < 65535)! ");

				} else {
					Port = get_port;
					PresentationLogic.set_Configuration(Configuration.SERVER_PORT, Port);

					PresentationLogic.msg("the Port will be bound to "
							+ Port + " when the Service started next time!",
							"Attention");

				}
			}
		});
		
		textField_Expiration.addKeyListener(new KeyAdapter(){  
            public void keyTyped(KeyEvent e) {  
                int keyChar = e.getKeyChar();                 
                if(keyChar >= KeyEvent.VK_0 && keyChar <= KeyEvent.VK_9){  
                      
                }else{  
                    e.consume();  
                }  
            }  
        });  
		
		textField_Port.addKeyListener(new KeyAdapter(){  
            public void keyTyped(KeyEvent e) {  
                int keyChar = e.getKeyChar();                 
                if(keyChar >= KeyEvent.VK_0 && keyChar <= KeyEvent.VK_9){  
                      
                }else{  
                    e.consume();  
                }  
            }  
        }); 
		
		btnApply.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				long expire=Long.valueOf(textField_Expiration.getText());
				if(expire>0)
				{

					int n = JOptionPane.showConfirmDialog(null, "Are you sure to set Expiration Time to "+expire+" ? If it's set too small, all the \"out-dated\" Assessments will be deleted !", "Are you Sure ?", JOptionPane.YES_NO_OPTION); 
					if(n == JOptionPane.YES_OPTION)
					{assessment_expiration_millis=expire;
					PresentationLogic.set_Configuration(Configuration.ASSESSMENT_EXPIRATION_MILLIS, assessment_expiration_millis);
					try {
						view = data.Model.openTrustView();
						view.clean();
						view.close();
					} catch (Exception arg) {
						JOptionPane
								.showConfirmDialog(
										null,
										"Error reading or concurrent modifying the database! ",
										"Error", JOptionPane.DEFAULT_OPTION);
						arg.printStackTrace();
					}

					table_Ass.setModel(PresentationLogic.refresh_Ass_Table());
					refresh_ColWidth();
					
					}else
					{
						textField_Expiration.setText(""+assessment_expiration_millis);
					}
					
				}
				else
				{
					
					PresentationLogic.msg("Please enter a valid Expiration Time in millisecond !" );
				}
				
			}
		});
		/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		JPanel panel_About = new JPanel();
		tabbedPane.addTab("About", null, panel_About, null);
		panel_About.setLayout(null);
		
		JTextPane txtpnTrustServiceApplication = new JTextPane();
		txtpnTrustServiceApplication.setBounds(136, 70, 292, 292);
		txtpnTrustServiceApplication.setEditable(false);
		txtpnTrustServiceApplication.setBackground(UIManager.getColor("Button.background"));
		txtpnTrustServiceApplication.setText("Trust Service Application\r\n\r\nVersion 1.0\r\n\r\nProduced by :\r\nJannik Vieten\r\nPascal Weisenburger\r\nHaixin Cai\r\n\r\nTU Darmstadt");
		panel_About.add(txtpnTrustServiceApplication);

		JToggleButton tglbtnStartService = new JToggleButton("Start Webserver");
		tglbtnStartService.setBounds(27, 534, 160, 23);
		tglbtnStartService.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent ev) {
	            if(ev.getStateChange()==ItemEvent.SELECTED) {
            		try {
            			server = new WebServer();
            			server.start();
    	            	((JToggleButton) ev.getSource()).setText("Stop Webserver");
						
					} catch (IOException e) {
						e.printStackTrace();
						((JToggleButton) ev.getSource()).setSelected(false);
					}
	            } else if(ev.getStateChange()==ItemEvent.DESELECTED) {
	            	server.stop();
	            	server = null;
	            	((JToggleButton) ev.getSource()).setText("Start Webserver");
	            }
	       }
		});
		frame.getContentPane().add(tglbtnStartService);

		JButton btnMiniminze = new JButton("Miniminze");
		btnMiniminze.setBounds(322, 534, 93, 23);
		btnMiniminze.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				frame.setExtendedState(JFrame.ICONIFIED);
			}
		});
		frame.getContentPane().add(btnMiniminze);

		JButton btnClose = new JButton("Close");
		btnClose.setBounds(462, 534, 93, 23);
		btnClose.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {
				System.exit(0);
			}
		});
		frame.getContentPane().add(btnClose);

	}
	
	public void refresh_ColWidth ()
	{
		
	
		
		
		if(table_TC!=null){
			DefaultTableColumnModel cmodel = (DefaultTableColumnModel)table_TC.getColumnModel();
			for (int i = 0; i < table_TC.getColumnCount(); i++) {
			TableColumn column = cmodel.getColumn(i);
			column.setPreferredWidth(PreferredWidth_TC[i]);
			}
		for(int i=0;i<Trust_Cert_TableCol.length;i++)
		{
			Trust_Cert_TableCol[i]= table_TC.getColumnModel().getColumn(i);
			Trust_Cert_TableCol[i].addPropertyChangeListener(new TC_ColumnListener ());
		}}
		
		
		
		if(table_uTC!=null){
			
			DefaultTableColumnModel cmodel = (DefaultTableColumnModel)table_uTC.getColumnModel();
				for (int i = 0; i < table_uTC.getColumnCount(); i++) {
				TableColumn column = cmodel.getColumn(i);
				column.setPreferredWidth(PreferredWidth_uTC[i]);
				}
				
			for(int i=0;i<UnTrust_Cert_TableCol.length;i++)
			{
			UnTrust_Cert_TableCol[i]= table_uTC.getColumnModel().getColumn(i);
		UnTrust_Cert_TableCol[i].addPropertyChangeListener(new uTC_ColumnListener ());
	}}
		
		
		
		if(table_Ass!=null){
			
			DefaultTableColumnModel cmodel = (DefaultTableColumnModel)table_Ass.getColumnModel();
				for (int i = 0; i < table_Ass.getColumnCount(); i++) {
				TableColumn column = cmodel.getColumn(i);
				column.setPreferredWidth(PreferredWidth_Ass[i]);
				}
				
				DefaultTableModel Model_Ass=(DefaultTableModel)table_Ass.getModel();
				Model_Ass.addTableModelListener(new Ass_ModelListener());
				
			for(int i=0;i<Ass_TableCol.length;i++)
			{
				Ass_TableCol[i]= table_Ass.getColumnModel().getColumn(i);
				Ass_TableCol[i].addPropertyChangeListener(new Ass_ColumnListener ());
	}}
	}
	
	class TC_ColumnListener implements PropertyChangeListener  {
	    public void propertyChange(PropertyChangeEvent e)  {
	         if (e.getPropertyName().equals("preferredWidth"))  {

	              TableColumn tableColumn= (TableColumn)e.getSource();
	              int index= table_TC.getColumnModel().getColumnIndex(tableColumn.getHeaderValue());
	              PreferredWidth_TC[index]=(int)e.getNewValue();
	              
	              

	        }}}
	
	class uTC_ColumnListener implements PropertyChangeListener  {
	    public void propertyChange(PropertyChangeEvent e)  {
	         if (e.getPropertyName().equals("preferredWidth"))  {

	              TableColumn tableColumn= (TableColumn)e.getSource();
	              int index= table_uTC.getColumnModel().getColumnIndex(tableColumn.getHeaderValue());
	              PreferredWidth_uTC[index]=(int)e.getNewValue();
	             

	        }}}
	
	class Ass_ColumnListener implements PropertyChangeListener  {
	    public void propertyChange(PropertyChangeEvent e)  {
	         if (e.getPropertyName().equals("preferredWidth"))  {

	              TableColumn tableColumn= (TableColumn)e.getSource();
	              int index= table_Ass.getColumnModel().getColumnIndex(tableColumn.getHeaderValue());
	              PreferredWidth_Ass[index]=(int)e.getNewValue();
	             

	        }}}
	
	
	  class  Ass_ModelListener implements TableModelListener {
	      public void tableChanged(TableModelEvent e) {
	 
	  TrustAssessment Clicked_Ass = PresentationLogic.getAss_by_Click(table_Ass);
	  TrustAssessment new_Ass=Clicked_Ass;
	  String Change=(String)table_Ass.getValueAt(e.getFirstRow(), e.getColumn());
	  
	  
	  String regex="^\\s*\\(\\s*(\\s*0\\.[0-9]+|1\\.0)\\s*,\\s*(0\\.[0-9]+|1\\.0)\\s*,\\s*(0\\.[0-9]+|1\\.0\\s*)\\s*\\)\\s*$";
	
	  if (!Change.matches(regex))
	  {
		  PresentationLogic.msg("Please enter the valid value(between 0.0 and 1.0) for each item. example:(0.5, 0.5, 0.5)");
		  
		  if(e.getColumn()==4)
		  Change= "(" + Clicked_Ass.getO_it_ca().getT() + ", "
					+ Clicked_Ass.getO_it_ca().getC() + ", "
					+ Clicked_Ass.getO_it_ca().getF() + ")";
		  else
			  if(e.getColumn()==5)
		  Change="(" + Clicked_Ass.getO_it_ee().getT() + ", "
						+ Clicked_Ass.getO_it_ee().getC() + ", "
						+ Clicked_Ass.getO_it_ee().getF() + ")";
		  
				  table_Ass.setValueAt(Change, e.getFirstRow(), e.getColumn());
			return;
	  }//if
	  
	  Change=Change.substring(Change.indexOf("(")+1, Change.indexOf(")"));
	  
	  double T,C,F;
	  String[] tcf = Change.split(",");
	  
	  T=Double.valueOf(tcf[0]);
	  C=Double.valueOf(tcf[1]);
	  F=Double.valueOf(tcf[2]);
	  CertainTrust new_CertT;
	  
	  if(e.getColumn()==4)
	  {  new_CertT=new CertainTrust(T, C, F, Clicked_Ass.getO_it_ca().getN());
	  new_CertT.setRS(Clicked_Ass.getO_it_ca().getR(), Clicked_Ass.getO_it_ca().getS());

	  new_Ass=new TrustAssessment(Clicked_Ass.getK(), Clicked_Ass.getCa(), Clicked_Ass.getS(), Clicked_Ass.getO_kl(), new_CertT, Clicked_Ass.getO_it_ee());
	  }
	  else if(e.getColumn()==5)
	  {
		  new_CertT=new CertainTrust(T, C, F, Clicked_Ass.getO_it_ee().getN());
		  new_Ass=new TrustAssessment(Clicked_Ass.getK(), Clicked_Ass.getCa(), Clicked_Ass.getS(), Clicked_Ass.getO_kl(), Clicked_Ass.getO_it_ca(), new_CertT);
	  }
	  
	  
	  try {
			TrustView view = data.Model.openTrustView();
			view.setAssessment(new_Ass);
			view.close();

		} catch (Exception e1) {
			PresentationLogic.msg("Error reading or concurrent modifying the database! ");
			
			e1.printStackTrace();
		}
	  
		table_Ass.setModel(PresentationLogic
				.refresh_Ass_Table());
		refresh_ColWidth();
	  
	      }
	    }
}

