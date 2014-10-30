package presentation.ui;

import java.awt.AWTException;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentEvent;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.UIManager;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import services.bindings.WebServer;
import support.Service;
import CertainTrust.CertainTrust;
import data.Configuration;
import data.Model;
import data.ModelAccessException;
import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

import javax.swing.JSeparator;

import java.awt.Color;

import javax.swing.JComboBox;

/**
 * the whole GUI interface for the Trustview application
 *
 */
/**
 * @author Haixin
 *
 */
public class GUI {

	public static String GUICONFIG_AUTO_START_WEBSERVER = "guiconfig-auto-start-webserver";
	private static JFrame frame;
	private JTabbedPane tabbedPane;
	private JTable table_TC;
	private JTable table_uTC;
	private JTable table_Ass;

	JScrollPane scrollPane_TC;
	JScrollPane scrollPane_uTC;
	JScrollPane scrollPane_Ass;

	private int[] PreferredWidth_TC = { 120, 145, 145, 123, 102, 102 };
	private int[] PreferredWidth_uTC = { 120, 145, 145, 123, 102, 102 };
	private int[] PreferredWidth_Ass = { 122, 157, 123, 89, 89 };
	TableColumn[] Trust_Cert_TableCol = new TableColumn[6];
	TableColumn[] UnTrust_Cert_TableCol = new TableColumn[6];
	TableColumn[] Ass_TableCol = new TableColumn[5];

	private JTextField textField_high;
	private JTextField textField_med;
	private JTextField textField_low;

	private TrustView view;

	private float security_level_low;
	private float security_level_med;
	private float security_level_high;

	private long assessment_expiration_millis;

	private int Port;
	private String Vali_Notary;

	private boolean Bootsrapping_Mode;
	private boolean AutoStart_Webserver;

	private JTextField textField_Expiration;
	private JTextField textField_Port;

	static SystemTray tray = SystemTray.getSystemTray();
	private static TrayIcon trayIcon = null;
	static JToggleButton tglbtnStartService = new JToggleButton(
			"Start Webserver");
	JButton btnRefresh;
	JButton btnMiniminze;
	JButton btnClose;

	int port;
	WebServer server;
	ImageIcon trayImg_on;
	ImageIcon trayImg_off;
	Dimension frame_size;
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) throws Exception {

		EventQueue.invokeLater(new Runnable() {
			@SuppressWarnings("static-access")
			@Override
			public void run() {
				GUI window = new GUI();
				window.frame.setVisible(true);
			}
		});
	}

	/**
	 * Create the application.
	 */
	public GUI() {
		Configurate();
		initialize();

		if (AutoStart_Webserver)
			tglbtnStartService.doClick();
	}



	/**
	 * load the application configuration from the database
	 */
	public void Configurate() {

		assessment_expiration_millis = GUILogic.get_Configuration(
				Configuration.ASSESSMENT_EXPIRATION_MILLIS, Long.class);

		Port = GUILogic.get_Configuration(Configuration.SERVER_PORT,
				Integer.class);

		security_level_low = GUILogic.get_Configuration(
				Configuration.SECURITY_LEVEL_LOW, Float.class);
		security_level_med = GUILogic.get_Configuration(
				Configuration.SECURITY_LEVEL_MEDIUM, Float.class);
		security_level_high = GUILogic.get_Configuration(
				Configuration.SECURITY_LEVEL_HIGH, Float.class);

		Vali_Notary= GUILogic.get_Configuration(
				Configuration.OVERRIDE_VALIDATION_SERVICE_RESULT, String.class);

		Bootsrapping_Mode = GUILogic.get_Configuration(
				Configuration.BOOTSTRAPPING_MODE, Boolean.class);

		AutoStart_Webserver = GUILogic.get_Configuration(
				GUICONFIG_AUTO_START_WEBSERVER, Boolean.class, false);
	}

	/**
	 * the icon and popup menu when app minimized to the systemtray
	 * @param on icon to be showed when service on
	 * @param off icon to be showed when service off
	 */
	private static void miniTray(ImageIcon on, ImageIcon off) {
		ImageIcon trayImg = null;
		if (tglbtnStartService.isSelected())
			trayImg = on;
		else
			trayImg = off;

		PopupMenu pop = new PopupMenu();
		MenuItem resume = new MenuItem("Resume");
		MenuItem exit = new MenuItem("Exit");

		resume.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				frame.setVisible(true);
				frame.setExtendedState(JFrame.NORMAL);
				frame.toFront();
				tray.remove(trayIcon);
			}

		});



		exit.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				tray.remove(trayIcon);
				System.exit(0);

			}

		});

		pop.add(resume);
		pop.add(exit);

		if (tglbtnStartService.isSelected())
			trayIcon = new TrayIcon(trayImg.getImage(), "Trust Service on", pop);
		else
			trayIcon = new TrayIcon(trayImg.getImage(), "Trust Service off",
					pop);

		trayIcon.setImageAutoSize(true);

		trayIcon.addMouseListener(new MouseAdapter() {

			@Override
			public void mouseClicked(MouseEvent e) {

				if (e.getClickCount() == 2) {

					frame.setVisible(true);
					frame.setExtendedState(JFrame.NORMAL);
					frame.toFront();
					tray.remove(trayIcon);
				}

			}
		});

		try {

			tray.add(trayIcon);

		} catch (AWTException e1) {

			e1.printStackTrace();
		}

	}



	  /**
	 * @param e , frame changes reacted to the Frame size change action
	 */
	void Frame_Resized(ComponentEvent e) {

		frame_size=frame.getSize();
		tglbtnStartService.setLocation(tglbtnStartService.getLocation().x, (int) (frame_size.getHeight()-82));
		btnRefresh.setLocation(btnRefresh.getLocation().x,  (int) (frame_size.getHeight()-82));
		btnMiniminze.setLocation(btnMiniminze.getLocation().x,  (int) (frame_size.getHeight()-82));
		btnClose.setLocation(btnClose.getLocation().x,  (int) (frame_size.getHeight()-82));
		tabbedPane.setSize((int)frame_size.getWidth()-36,(int) frame_size.getHeight()-113);
		scrollPane_TC.setSize((int)frame_size.getWidth()-61,(int) frame_size.getHeight()-163);
		scrollPane_uTC.setSize((int)frame_size.getWidth()-61,(int) frame_size.getHeight()-163);
		scrollPane_Ass.setSize((int)frame_size.getWidth()-61,(int) frame_size.getHeight()-163);

		  }


	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {

		try {
			UIManager
					.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
		} catch (Exception e) {
		}

		frame = new JFrame("CA Trust Management System");
		frame.setResizable(true);
		frame.setBounds(100, 100, 610, 660);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);
		frame.addComponentListener(new componentAdapter(this));
		frame.setMinimumSize(new Dimension(610,730));


		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane.setBounds(10, 10, 574, 547);
		frame.getContentPane().add(tabbedPane);

		JPanel panel_TC = new JPanel();
		tabbedPane.addTab("Trusted Certificates", null, panel_TC, null);
		panel_TC.setLayout(null);

		scrollPane_TC = new JScrollPane();
		scrollPane_TC.setBounds(10, 10, 549, 497);
		panel_TC.add(scrollPane_TC);

		trayImg_on = new ImageIcon(
				getClass().getClassLoader().getResource("images/on.png"));
		trayImg_off = new ImageIcon(
				getClass().getClassLoader().getResource("images/off.png"));



		// ///////////////////////////////////////////////////////////////////TrustCertificate_Table////////////////////////////////////////////////////////////

		table_TC = new JTable(GUILogic.refresh_TC_Table());

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
			@Override
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
			@Override
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

		// /////////////////////////////////////////////////////////////////////////Insert
		// menu//////////////////////////////////
		Insert_TC.addMouseListener(new MouseAdapter() {
			@Override
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
					if (!new File(Cert_Path).exists()) {
						GUILogic.msg("File not found!");
						return;
					}

					try {
						X509Certificate cert = GUILogic
								.LoadCert(Cert_Path);
						TrustView view = data.Model.openTrustView();
						view.setTrustedCertificate(new TrustCertificate(cert));
						view.close();

						table_TC.setModel(GUILogic.refresh_TC_Table());
						table_uTC.setModel(GUILogic
								.refresh_uTC_Table());
						refresh_ColWidth();

					} catch (CertificateException e) {
						GUILogic.msg("Cannot create a TrustCertificate from not X.509 Certificate ");
						e.printStackTrace();
					} catch (IOException e) {
						if (Cert_Path.equals(""))
							return;
						else
							GUILogic.msg("Error reading Certificate File ");

						e.printStackTrace();
					} catch (ModelAccessException e) {
						GUILogic.msg("Error reading or concurrent modifying the database! ");

						e.printStackTrace();
					}

				}
			}
		});
		// ////////////////////////////////////////////////////////////Delete//////////////////////////////////////////////////////////
		Delete_TC.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					TrustCertificate Cert = GUILogic.getTCert_by_Click(table_TC);
					if (Cert == null)
						return;

					try {
						view = data.Model.openTrustView();
						view.removeCertificate(Cert);
						view.close();

						table_TC.setModel(GUILogic.refresh_TC_Table());
						refresh_ColWidth();

					} catch (ModelAccessException e) {

						GUILogic.msg("Error reading or concurrent modifying the database! ");

						e.printStackTrace();
					}

				}
			}
		});
		// ////////////////////////////////////////////////////////////Set
		// untrust////////////////////////////////////////////////////
		Set_uTC.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					TrustCertificate uTCertificate = GUILogic
							.getTCert_by_Click(table_TC);
					if (uTCertificate == null)
						return;

					try {
						view = data.Model.openTrustView();
						view.setUntrustedCertificate(uTCertificate);
						view.close();

						table_TC.setModel(GUILogic.refresh_TC_Table());
						table_uTC.setModel(GUILogic.refresh_uTC_Table());
						refresh_ColWidth();

					} catch (ModelAccessException e) {

						GUILogic.msg("Error reading or concurrent modifying the database !");

						e.printStackTrace();
					}

				}
			}
		});

		// ///////////////////////////////////////////////////////////////////unTrustCertificate_panel///////////////////////////////////////////

		JPanel panel_uTC = new JPanel();
		tabbedPane.addTab("unTrusted Certificates", null, panel_uTC, null);
		panel_uTC.setLayout(null);

		scrollPane_uTC = new JScrollPane();
		scrollPane_uTC.setBounds(10, 10, 549, 497);
		panel_uTC.add(scrollPane_uTC);
		// ///////////////////////////////////////////////////////////////////unTrustCertificate_Table////////////////////////////////////

		table_uTC = new JTable(GUILogic.refresh_uTC_Table());
		table_uTC.setFont(new Font("Arial", Font.PLAIN, 14));
		table_uTC.setRowHeight(25);
		table_uTC.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		refresh_ColWidth();
		scrollPane_uTC.setViewportView(table_uTC);

		// /////////////////////////////////////////////////Popupmenu for
		// unTrustCertificate_Table////////////////////////////

		final JPopupMenu PopMenu_unTrustCert = new JPopupMenu();
		final JMenuItem Insert_uTC = new JMenuItem("Insert");
		final JMenuItem Delete_uTC = new JMenuItem("Delete");
		final JMenuItem Set_TC = new JMenuItem("Set trust");

		PopMenu_unTrustCert.add(Insert_uTC);
		PopMenu_unTrustCert.add(Delete_uTC);
		PopMenu_unTrustCert.add(Set_TC);

		// //////////////////////////////////////////////////////////////////Listener
		// for POPUP////////////////////////////////////////////////////

		table_uTC.addMouseListener(new MouseAdapter() {
			@Override
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
			@Override
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

		// //////////////////////////////////////////////////Insert for
		// unTrustCertificate//////////////////////////////////////////////////////
		Insert_uTC.addMouseListener(new MouseAdapter() {
			@Override
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

					if (!new File(Cert_Path).exists()) {
						GUILogic.msg("File not found!");
						return;
					}

					try {
						X509Certificate cert = GUILogic
								.LoadCert(Cert_Path);
						TrustView view = data.Model.openTrustView();
						view.setUntrustedCertificate(new TrustCertificate(cert));
						view.close();

						table_uTC.setModel(GUILogic
								.refresh_uTC_Table());
						table_TC.setModel(GUILogic.refresh_TC_Table());
						refresh_ColWidth();

					} catch (CertificateException e) {
						GUILogic.msg("Cannot create a TrustCertificate from not X.509 Certificate ");

						e.printStackTrace();
					} catch (IOException e) {
						if (Cert_Path.equals(""))
							return;
						else
							GUILogic.msg("Error reading Certificate File ");

						e.printStackTrace();
					} catch (ModelAccessException e) {
						GUILogic.msg("Error reading or concurrent modifying the database! ");

						e.printStackTrace();
					}

				}
			}
		});
		// /////////////////////////////////////////////////////////////////Delete_uTC/////////////////////////////////////////////////////////////
		Delete_uTC.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					TrustCertificate Cert = GUILogic
							.getuTCert_by_Click(table_uTC);
					if (Cert == null) {
						return;
					}

					try {
						view = data.Model.openTrustView();
						view.removeCertificate(Cert);
						view.close();

						table_uTC.setModel(GUILogic
								.refresh_uTC_Table());
						refresh_ColWidth();

					} catch (ModelAccessException e) {

						GUILogic.msg("Error reading or concurrent modifying the database! ");

						e.printStackTrace();
					}

				}
			}
		});

		// /////////////////////////////////////////////////////////////////Set_TC/////////////////////////////////////////////////////////////
		Set_TC.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					TrustCertificate TCertificate = GUILogic
							.getuTCert_by_Click(table_uTC);

					if (TCertificate == null)
						return;

					try {
						view = data.Model.openTrustView();
						view.setTrustedCertificate(TCertificate);
						view.close();

						table_TC.setModel(GUILogic.refresh_TC_Table());
						table_uTC.setModel(GUILogic
								.refresh_uTC_Table());
						refresh_ColWidth();

					} catch (ModelAccessException e) {
						GUILogic
								.msg("Error reading or concurrent modifying the database! ");

						e.printStackTrace();
					}

				}
			}
		});

		// ///////////////////////////////////////////////////////////////////panel_Ass/////////////////////////////////////////////

		JPanel panel_Ass = new JPanel();
		tabbedPane.addTab("Assessments Management", null, panel_Ass, null);
		panel_Ass.setLayout(null);

		scrollPane_Ass = new JScrollPane();
		scrollPane_Ass.setBounds(10, 10, 549, 497);
		panel_Ass.add(scrollPane_Ass);
		// ///////////////////////////////////////////////////////////////////Assessment_Table///////////////////////////////////

		table_Ass = new JTable(GUILogic.refresh_Ass_Table());
		table_Ass.setFont(new Font("Arial", Font.PLAIN, 14));
		table_Ass.setRowHeight(25);
		table_Ass.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		refresh_ColWidth();
		scrollPane_Ass.setViewportView(table_Ass);
		// //////////////////////////////////////////////Popupmenufor
		// ASS//////////////////////////////////////////////////////////

		final JPopupMenu PopMenu_Ass = new JPopupMenu();
		final JMenuItem Delete_Ass = new JMenuItem("Delete");
		final JMenuItem Edit_Ass = new JMenuItem("Edit");
		final JMenuItem Set_Valid_Ass = new JMenuItem("Set Valid");
		final JMenuItem Clean_Ass = new JMenuItem("Clean Assessments");

		PopMenu_Ass.add(Edit_Ass);
		PopMenu_Ass.add(Delete_Ass);
		PopMenu_Ass.add(Set_Valid_Ass);
		PopMenu_Ass.add(Clean_Ass);
		// /////////////////////////////////////////////\////////////////////Listener
		// for Ass//////////////////////////////////////////////////
		table_Ass.addMouseListener(new MouseAdapter() {
			@Override
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
			@Override
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
			@Override
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					TrustAssessment Ass = GUILogic
							.getAss_by_Click(table_Ass);
					if (Ass == null)
						return;

					try {
						view = data.Model.openTrustView();
						view.removeAssessment(Ass.getK(), Ass.getCa());
						view.close();

						table_Ass.setModel(GUILogic
								.refresh_Ass_Table());
						refresh_ColWidth();

					} catch (ModelAccessException e) {

						GUILogic.msg("Error reading or concurrent modifying the database! ");

						e.printStackTrace();
					}

				}
			}
		});

		// //////////////////////////////////////////////////////////Edit_Ass/////////////////////////////////////////////////////
		Edit_Ass.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					table_Ass.editCellAt(table_Ass.getSelectedRow(), 3);

				}
			}
		});
		// /////////////////////////////////////////////////////////////////Set_Valid_Ass/////////////////////////////////////////////////
		Set_Valid_Ass.addMouseListener(new MouseAdapter() {
			@Override
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
					} catch (ModelAccessException e) {
						GUILogic.msg("Error reading or concurrent modifying the database! ");

					}

				}
			}
		});
		// ////////////////////////////////////////////////////////////////////////Clean_Ass//////////////////////////////////////////////////////
		Clean_Ass.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1 || arg0.getButton() == 3) {

					try {
						view = data.Model.openTrustView();
						view.clean();
						view.close();
					} catch (ModelAccessException e) {
						GUILogic.msg("Error reading or concurrent modifying the database! ");

						e.printStackTrace();
					}

					table_Ass.setModel(GUILogic.refresh_Ass_Table());
					refresh_ColWidth();
				}
			}
		});
		// //////////////////////////////////////////////////////////////////////////configuration
		// pannel///////////////////////////////////////////////
		final JPanel panel_Conf = new JPanel();
		tabbedPane.addTab("Configuration", null, panel_Conf, null);
		panel_Conf.setLayout(null);

		JPanel Outer_Security_Level = new JPanel();
		Outer_Security_Level.setBounds(10, 10, 549, 123);
		Outer_Security_Level.setBorder(BorderFactory
				.createTitledBorder("Security Level Setting"));
		Outer_Security_Level.setLayout(null);
		panel_Conf.add(Outer_Security_Level);
		// ///////////////////////////////////////////////////////////Security
		// level setting
		// panel/////////////////////////////////////////////////////
		final JSlider slider_high = new JSlider();
		slider_high.setValue((int) (security_level_high * 100));
		slider_high.setBounds(30, 24, 143, 26);
		Outer_Security_Level.add(slider_high);

		final JSlider slider_med = new JSlider();
		slider_med.setBounds(203, 24, 143, 26);
		slider_med.setValue((int) (security_level_med * 100));
		Outer_Security_Level.add(slider_med);

		final JSlider slider_low = new JSlider();
		slider_low.setBounds(376, 24, 143, 26);
		slider_low.setValue((int) (security_level_low * 100));
		Outer_Security_Level.add(slider_low);

		JLabel label_min_high = new JLabel("0.0");
		label_min_high.setBounds(20, 49, 30, 15);
		Outer_Security_Level.add(label_min_high);

		JLabel label_max_high = new JLabel("1.0");
		label_max_high.setBounds(153, 49, 30, 15);
		Outer_Security_Level.add(label_max_high);

		textField_high = new JTextField("" + (float) slider_high.getValue()
				/ 100);
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
		lblMedium.setBounds(225, 75, 65, 15);
		Outer_Security_Level.add(lblMedium);

		JLabel lblLow = new JLabel("Low:");
		lblLow.setBounds(419, 75, 54, 15);
		Outer_Security_Level.add(lblLow);

		JPanel Outer_General_Setting = new JPanel();
		Outer_General_Setting.setBorder(new TitledBorder(null,
				"General Setting", TitledBorder.LEADING, TitledBorder.TOP,
				null, null));
		Outer_General_Setting.setBounds(10, 143, 549, 387);
		panel_Conf.add(Outer_General_Setting);
		Outer_General_Setting.setLayout(null);

		JLabel lblNewLabel_1 = new JLabel(
				"Assessment Expiration (in Milliseconds):");
		lblNewLabel_1.setBounds(10, 29, 270, 15);
		Outer_General_Setting.add(lblNewLabel_1);

		textField_Expiration = new JTextField();
		textField_Expiration.setBounds(264, 26, 172, 21);
		textField_Expiration.setText("" + assessment_expiration_millis);
		Outer_General_Setting.add(textField_Expiration);
		textField_Expiration.setColumns(10);

		JButton btnApply = new JButton("Apply");

		btnApply.setBounds(446, 25, 93, 23);
		Outer_General_Setting.add(btnApply);

		JLabel lblBindingPortFor = new JLabel("Binding Port for Trust Service:");
		lblBindingPortFor.setBounds(139, 70, 220, 15);
		Outer_General_Setting.add(lblBindingPortFor);

		textField_Port = new JTextField();
		textField_Port.setBounds(370, 67, 66, 21);
		textField_Port.setText("" + Port);
		Outer_General_Setting.add(textField_Port);
		textField_Port.setColumns(10);

		JButton btnChange = new JButton("Change");

		btnChange.setBounds(446, 66, 93, 23);
		Outer_General_Setting.add(btnChange);

		JSeparator separator = new JSeparator();
		separator.setForeground(Color.LIGHT_GRAY);
		separator.setBounds(120, 171, 419, 11);
		Outer_General_Setting.add(separator);

		JLabel lblResetDatabase = new JLabel("Reset trust view");
		lblResetDatabase.setBounds(10, 162, 100, 15);
		Outer_General_Setting.add(lblResetDatabase);

		JLabel lblDeleteAllThe = new JLabel(
				"All of the Trust/Untrust Certificates, Assessments will");
		lblDeleteAllThe.setBounds(42, 183, 343, 15);
		Outer_General_Setting.add(lblDeleteAllThe);

		JLabel lblAndAllThe = new JLabel("be deleted.");
		lblAndAllThe.setBounds(42, 201, 343, 15);
		Outer_General_Setting.add(lblAndAllThe);

		JButton btnReset = new JButton("Reset");

		btnReset.setBounds(422, 187, 93, 23);
		Outer_General_Setting.add(btnReset);

		JSeparator separator_1 = new JSeparator();
		separator_1.setForeground(Color.LIGHT_GRAY);
		separator_1.setBounds(74, 240, 465, 2);
		Outer_General_Setting.add(separator_1);

		JLabel lblBootstrapWithBrowserHistory = new JLabel("Bootstrap");
		lblBootstrapWithBrowserHistory.setBounds(10, 231, 64, 15);
		Outer_General_Setting.add(lblBootstrapWithBrowserHistory);

		JLabel lblBootstrap = new JLabel(
				"Bootstrap trust view by scanning the browser history");
		lblBootstrap.setBounds(42, 252, 359, 15);
		Outer_General_Setting.add(lblBootstrap);

		JLabel lblBootstrap_2 = new JLabel("using the medium security level");
		lblBootstrap_2.setBounds(42, 270, 343, 15);
		Outer_General_Setting.add(lblBootstrap_2);

		final JCheckBox BootstrappingMode = new JCheckBox("Enable bootstrapping mode");
		BootstrappingMode.setSelected(Bootsrapping_Mode);
		BootstrappingMode.setBounds(42, 293, 343, 15);
		Outer_General_Setting.add(BootstrappingMode);

		JButton btnBootstrap = new JButton("Bootstrap");

		btnBootstrap.setBounds(422, 251, 93, 23);
		Outer_General_Setting.add(btnBootstrap);

		JSeparator separator_2 = new JSeparator();
		separator_2.setForeground(Color.LIGHT_GRAY);
		separator_2.setBounds(149, 329, 390, 2);
		Outer_General_Setting.add(separator_2);

		JLabel lblDefaultSetting = new JLabel("Default configuration");
		lblDefaultSetting.setBounds(10, 320, 129, 15);
		Outer_General_Setting.add(lblDefaultSetting);

		JLabel lblAllOfThe = new JLabel(
				"All of the configurations will be set to default value.");
		lblAllOfThe.setBounds(42, 346, 359, 15);
		Outer_General_Setting.add(lblAllOfThe);

		JButton btnDefault = new JButton("Default");

		btnDefault.setBounds(422, 346, 93, 23);
		Outer_General_Setting.add(btnDefault);

		JLabel lblValidationNortaries = new JLabel("Validation Nortary Results Override With:");
		lblValidationNortaries.setBounds(160, 117, 276, 15);
		Outer_General_Setting.add(lblValidationNortaries);

		Vector<String> Choices = new Vector<String>();
		Choices.add("trusted");
		Choices.add("untrusted");
		Choices.add("unknown");
		Choices.add("off");
		final JComboBox<String> comboBox = new JComboBox<String>(Choices);
		comboBox.setSelectedItem(Vali_Notary);

		comboBox.setBounds(446, 109, 93, 21);
		Outer_General_Setting.add(comboBox);

		JLabel lblAutoStartWebserver = new JLabel("Start webserver when application starts");
		lblAutoStartWebserver.setBounds(160, 144, 276, 15);
		Outer_General_Setting.add(lblAutoStartWebserver);

		final JCheckBox AutoStartWebserver = new JCheckBox();
		AutoStartWebserver.setSelected(AutoStart_Webserver);
		AutoStartWebserver.setBounds(444, 141, 89, 21);
		Outer_General_Setting.add(AutoStartWebserver);

		JPanel Outer_Data_Backup = new JPanel();
		Outer_Data_Backup.setBorder(new TitledBorder(null, "Data Backup",
				TitledBorder.LEADING, TitledBorder.TOP, null, null));
		Outer_Data_Backup.setBounds(10, 541, 549, 62);
		panel_Conf.add(Outer_Data_Backup);
		Outer_Data_Backup.setLayout(null);

		JButton btnImport = new JButton("Import");

		btnImport.setBounds(107, 27, 93, 23);
		Outer_Data_Backup.add(btnImport);

		JButton btnExport = new JButton("Export");

		btnExport.setBounds(345, 27, 93, 23);
		Outer_Data_Backup.add(btnExport);
		// /////////////////////////////////////////////////////////////////////////////////Security
		// level setting
		// listner//////////////////////////////////////////////////////////////////////////////
		slider_high.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent event) {
				if ((JSlider) event.getSource() == slider_high) {
					float val = (float) slider_high.getValue() / 100;
					String str = "" + val;
					textField_high.setText(str);

					if (!slider_high.getValueIsAdjusting()) {
						if (slider_high.getValue() <= slider_med.getValue()) {
							GUILogic.msg("Please select a correct value(not smaller than medium level)! ");

							slider_high
									.setValue((int) (security_level_high * 100));

						} else {

							security_level_high = (float) slider_high
									.getValue() / 100;
							GUILogic.set_Configuration(
									Configuration.SECURITY_LEVEL_HIGH,
									security_level_high);

						}
					}
				}
			}
		});

		slider_med.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent event) {
				if ((JSlider) event.getSource() == slider_med) {
					float val = (float) slider_med.getValue() / 100;
					String str = "" + val;
					textField_med.setText(str);

					if (!slider_med.getValueIsAdjusting()) {
						if (slider_med.getValue() >= slider_high.getValue()
								|| slider_med.getValue() <= slider_low
										.getValue()) {
							GUILogic.msg("Please select a correct value(not bigger than high level and not smaller than low level)! ");

							slider_med
									.setValue((int) (security_level_med * 100));

						} else {

							security_level_med = (float) slider_med.getValue() / 100;
							GUILogic.set_Configuration(
									Configuration.SECURITY_LEVEL_MEDIUM,
									security_level_med);

						}
					}

				}
			}
		});

		slider_low.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent event) {
				if ((JSlider) event.getSource() == slider_low) {
					float val = (float) slider_low.getValue() / 100;
					String str = "" + val;
					textField_low.setText(str);

					if (!slider_low.getValueIsAdjusting()) {
						if (slider_med.getValue() <= slider_low.getValue()) {
							GUILogic.msg("Please select a correct value(not bigger medium level)! ");

							slider_low
									.setValue((int) (security_level_low * 100));

						} else {

							security_level_low = (float) slider_low.getValue() / 100;
							GUILogic.set_Configuration(
									Configuration.SECURITY_LEVEL_LOW,
									security_level_low);

						}
					}

				}
			}
		});

		// //////////////////////////////////////////////////////////////////////////////Backup
		// listner/////////////////////////////////////////////////////

		btnImport.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {
				String Import_Path = "";
				JFileChooser Import_Chooser = new JFileChooser();
				Import_Chooser.setFileSelectionMode(JFileChooser.OPEN_DIALOG);
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

				if (!new File(Import_Path).exists()) {
					GUILogic.msg("Import Backup File not exist !");
					return;
				}

				try {

					Model.restore(new File(Import_Path));

				} catch (ModelAccessException e) {
					GUILogic.msg("Importing Backup File Error !");
					e.printStackTrace();
					return;
				}

				table_TC.setModel(GUILogic.refresh_TC_Table());
				table_uTC.setModel(GUILogic.refresh_uTC_Table());
				table_Ass.setModel(GUILogic.refresh_Ass_Table());

				refresh_ColWidth();

				GUILogic.msg("Success Importing Backup File !", "Success");
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
					Export_Chooser
							.setFileSelectionMode(JFileChooser.APPROVE_OPTION);
					Export_Chooser.setDialogType(JFileChooser.SAVE_DIALOG);
					Export_Chooser.setApproveButtonText("Save");
					FileFilter Export_filter = new FileNameExtensionFilter(
							"Trust Service Backup File(.bak)", "bak");
					Export_Chooser.setFileFilter(Export_filter);

					int returnVal = Export_Chooser.showSaveDialog(panel_Conf);

					if (returnVal == JFileChooser.APPROVE_OPTION) {

						Export_Path = Export_Chooser.getSelectedFile()
								.getAbsolutePath();
					}

					Export_File = new File(Export_Path);

					if (!Export_Path.endsWith(".bak"))
						Export_Path = Export_Path + ".bak";

					if (Export_File.exists()) {
						int n = JOptionPane.showConfirmDialog(null,
								"Are you sure to overwrite file "
										+ new File(Export_Path).getName()
										+ " with the new backup file ?",
								"Are you Sure ?", JOptionPane.YES_NO_OPTION);
						if (n == JOptionPane.NO_OPTION)
							return;
					}

					if (!Export_Path.equals(".bak")) {
						try {

							Model.backup(Export_File);

						} catch (ModelAccessException e) {
							GUILogic.msg("Exporting Backup File Error !");
							e.printStackTrace();
							return;
						}

						GUILogic.msg("Success Exporting Backup File !", "Success");

					}
				}

			}
		});



		// /////////////////////////////////////////////////////////////////////////////////General
		// setting
		// setting//////////////////////////////////////////////////////////////////////////////

		AutoStartWebserver.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				GUILogic.set_Configuration(
						GUICONFIG_AUTO_START_WEBSERVER, AutoStartWebserver.isSelected());
			}
		});

		BootstrappingMode.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				GUILogic.set_Configuration(
						Configuration.BOOTSTRAPPING_MODE, BootstrappingMode.isSelected());
			}
		});

		comboBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				if(arg0.getSource()==comboBox)
				{
					GUILogic.set_Configuration(Configuration.OVERRIDE_VALIDATION_SERVICE_RESULT, comboBox.getSelectedItem().toString());
				}
			}
		});

		btnChange.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {
				int get_port = Integer.valueOf(textField_Port.getText());
				if (get_port < 200 || get_port > 65535) {
					GUILogic.msg("Please enter a valid Port Number(200 < Number < 65535)! ");

				} else {
					Port = get_port;
					GUILogic.set_Configuration(
							Configuration.SERVER_PORT, Port);

					GUILogic.msg("The service will be bound to port "
							+ Port + " when it is started next time!",
							"Attention");

				}
			}
		});

		textField_Expiration.addKeyListener(new KeyAdapter() {
			@Override
			public void keyTyped(KeyEvent e) {
				int keyChar = e.getKeyChar();
				if (keyChar >= KeyEvent.VK_0 && keyChar <= KeyEvent.VK_9) {

				} else {
					e.consume();
				}
			}
		});

		textField_Port.addKeyListener(new KeyAdapter() {
			@Override
			public void keyTyped(KeyEvent e) {
				int keyChar = e.getKeyChar();
				if (keyChar >= KeyEvent.VK_0 && keyChar <= KeyEvent.VK_9) {

				} else {
					e.consume();
				}
			}
		});

		btnApply.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				long expire = Long.valueOf(textField_Expiration.getText());
				if (expire > 0) {

					int n = JOptionPane
							.showConfirmDialog(
									null,
									"Are you sure to set Expiration Time to "
											+ expire
											+ " ? If it's set too small, all the \"out-dated\" Assessments will be deleted !",
									"Are you Sure ?", JOptionPane.YES_NO_OPTION);
					if (n == JOptionPane.YES_OPTION) {
						assessment_expiration_millis = expire;
						GUILogic.set_Configuration(
								Configuration.ASSESSMENT_EXPIRATION_MILLIS,
								assessment_expiration_millis);
						try {
							view = data.Model.openTrustView();
							view.clean();
							view.close();
						} catch (ModelAccessException arg) {
							JOptionPane
									.showConfirmDialog(
											null,
											"Error reading or concurrent modifying the database! ",
											"Error", JOptionPane.DEFAULT_OPTION);
							arg.printStackTrace();
						}

						table_Ass.setModel(GUILogic.refresh_Ass_Table());
						refresh_ColWidth();

					} else {
						textField_Expiration.setText(""
								+ assessment_expiration_millis);
					}

				} else {

					GUILogic.msg("Please enter a valid Expiration Time in millisecond !");
				}

			}
		});


		btnReset.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {

				int n = JOptionPane.showConfirmDialog(null,
						"Are you sure to reset all the data in the database ?",
						"Are you Sure ?", JOptionPane.YES_NO_OPTION);
				if (n == JOptionPane.YES_OPTION) {
					try {
						view = data.Model.openTrustView();
						view.erase();
						view.close();
					} catch (ModelAccessException e) {
						JOptionPane
								.showConfirmDialog(
										null,
										"Error reading or concurrent modifying the database! ",
										"Error", JOptionPane.DEFAULT_OPTION);
						e.printStackTrace();
					}
					table_TC.setModel(GUILogic.refresh_TC_Table());
					table_uTC.setModel(GUILogic.refresh_uTC_Table());
					table_Ass.setModel(GUILogic.refresh_Ass_Table());
					refresh_ColWidth();

				}
			}

		});

		btnBootstrap.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent evt) {
				final double securityLevel;
				try (Configuration config = Model.openConfiguration()) {
					securityLevel = config.get(
							Configuration.SECURITY_LEVEL_MEDIUM, Double.class);
				}
				catch (ModelAccessException e) {
					e.printStackTrace();
					return;
				}

				final JButton button = (JButton) evt.getSource();

				List<File> files = Service.findBoostrapBaseFiles();

				JPopupMenu popup = new JPopupMenu();
				for (final File file : files) {
					JMenuItem item = new JMenuItem(file.getPath());
					popup.add(item);
					item.addActionListener(new ActionListener() {
						@Override
						public void actionPerformed(ActionEvent evt) {
							GUILogic.bootstrapTrustView(
									file, securityLevel, frame);
						}
					});
				}

				if (!files.isEmpty())
					popup.addSeparator();

				JMenuItem item = new JMenuItem("Choose bootstrapping base ...");
				popup.add(item);
				item.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent evt) {
						JFileChooser fileChooser = new JFileChooser();
						fileChooser.setFileSelectionMode(
								JFileChooser.FILES_AND_DIRECTORIES);

						if (fileChooser.showOpenDialog(button) ==
								JFileChooser.APPROVE_OPTION) {
							GUILogic.bootstrapTrustView(
									fileChooser.getSelectedFile(), securityLevel, frame);
						}
					}
				});

				popup.show(button, 0, button.getHeight());
			}
		});

		btnDefault.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {
				int n = JOptionPane
						.showConfirmDialog(
								null,
								"Are you sure to restore the configurations of the application ? This function should only be used if the Application is in an unusable state !",
								"Are you Sure ?", JOptionPane.YES_NO_OPTION);
				if (n == JOptionPane.YES_OPTION) {

					Configuration conf;
					try {
						conf = data.Model.openConfiguration();
						conf.erase();
						conf.close();
					} catch (ModelAccessException e) {
						JOptionPane
								.showConfirmDialog(
										null,
										"Error reading or concurrent modifying the database! ",
										"Error", JOptionPane.DEFAULT_OPTION);
						e.printStackTrace();
					}

					JOptionPane
							.showConfirmDialog(
									null,
									"All of the configurations are restored, please restart the application !",
									"Please restart the Application !",
									JOptionPane.DEFAULT_OPTION);
				}
			}
		});
		// ///////////////////////////////////////////////////////////////panel_About////////////////////////////////////////////////////////////////////

		JPanel panel_About = new JPanel();
		tabbedPane.addTab("About", null, panel_About, null);
		panel_About.setLayout(null);

		JTextPane txtpnTrustServiceApplication = new JTextPane();
		txtpnTrustServiceApplication.setBounds(136, 70, 292, 292);
		txtpnTrustServiceApplication.setEditable(false);
		txtpnTrustServiceApplication.setBackground(UIManager
				.getColor("Button.background"));
		txtpnTrustServiceApplication
				.setText("Trust Service Application\r\n\r\nVersion 1.0\r\n\r\nProduced by :\r\nJannik Vieten\r\nPascal Weisenburger\r\nHaixin Cai\r\n\r\nTU Darmstadt");
		panel_About.add(txtpnTrustServiceApplication);

		// ///////////////////////////////////////////////////////////////JToggleButton////////////////////////////////////////////////////////////////////

		tglbtnStartService.setBounds(27, 578, 160, 23);
		tglbtnStartService.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent ev) {
				if (ev.getStateChange() == ItemEvent.SELECTED) {
					try {
						server = new WebServer();
						server.start();
						((JToggleButton) ev.getSource())
								.setText("Stop Webserver");

					} catch (IOException e) {
						e.printStackTrace();
						((JToggleButton) ev.getSource()).setSelected(false);
					}
				} else if (ev.getStateChange() == ItemEvent.DESELECTED) {
					server.stop();
					server = null;
					((JToggleButton) ev.getSource()).setText("Start Webserver");
				}
			}
		});
		frame.getContentPane().add(tglbtnStartService);
		// ///////////////////////////////////////////////////////////////////////////Minimize//////////////////////////////////////////////////////////////
		btnMiniminze = new JButton("Minimize");
		btnMiniminze.setBounds(359, 578, 100, 23);
		btnMiniminze.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				frame.setVisible(false);
				miniTray(trayImg_on, trayImg_off);
			}
		});
		frame.getContentPane().add(btnMiniminze);
		// ////////////////////////////////////////////////////////////////////////////Close/////////////////////////////////////////////////////////////
		btnClose = new JButton("Close");
		btnClose.setBounds(475, 578, 93, 23);
		btnClose.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {
				System.exit(0);
			}
		});
		frame.getContentPane().add(btnClose);
		// ////////////////////////////////////////////////////////////////////////Refresh///////////////////////////////////////////////////////////
		btnRefresh = new JButton("Refresh");
		btnRefresh.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent arg0) {

				table_TC.setModel(GUILogic.refresh_TC_Table());
				table_uTC.setModel(GUILogic.refresh_uTC_Table());
				table_Ass.setModel(GUILogic.refresh_Ass_Table());
				refresh_ColWidth();

			}
		});
		btnRefresh.setBounds(245, 578, 93, 23);
		frame.getContentPane().add(btnRefresh);

		// /////////////////////////////////////////////////////////////////////close////////////////////////////////////////////////////////////////
		frame.addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				System.exit(0);
			};

			@Override
			public void windowIconified(WindowEvent e) {

				frame.setVisible(false);
				miniTray(trayImg_on, trayImg_off);

			}

		});

	}


	/**
	 * to refresh the table with the modified colum width
	 */
	public void refresh_ColWidth() {

		if (table_TC != null) {
			DefaultTableColumnModel cmodel = (DefaultTableColumnModel) table_TC
					.getColumnModel();
			for (int i = 0; i < table_TC.getColumnCount(); i++) {
				TableColumn column = cmodel.getColumn(i);
				column.setPreferredWidth(PreferredWidth_TC[i]);
			}
			for (int i = 0; i < Trust_Cert_TableCol.length; i++) {
				Trust_Cert_TableCol[i] = table_TC.getColumnModel().getColumn(i);
				Trust_Cert_TableCol[i]
						.addPropertyChangeListener(new TC_ColumnListener());
			}
		}

		if (table_uTC != null) {

			DefaultTableColumnModel cmodel = (DefaultTableColumnModel) table_uTC
					.getColumnModel();
			for (int i = 0; i < table_uTC.getColumnCount(); i++) {
				TableColumn column = cmodel.getColumn(i);
				column.setPreferredWidth(PreferredWidth_uTC[i]);
			}

			for (int i = 0; i < UnTrust_Cert_TableCol.length; i++) {
				UnTrust_Cert_TableCol[i] = table_uTC.getColumnModel()
						.getColumn(i);
				UnTrust_Cert_TableCol[i]
						.addPropertyChangeListener(new uTC_ColumnListener());
			}
		}

		if (table_Ass != null) {

			DefaultTableColumnModel cmodel = (DefaultTableColumnModel) table_Ass
					.getColumnModel();
			for (int i = 0; i < table_Ass.getColumnCount(); i++) {
				TableColumn column = cmodel.getColumn(i);
				column.setPreferredWidth(PreferredWidth_Ass[i]);
			}

			DefaultTableModel Model_Ass = (DefaultTableModel) table_Ass
					.getModel();
			Model_Ass.addTableModelListener(new Ass_ModelListener());

			for (int i = 0; i < Ass_TableCol.length; i++) {
				Ass_TableCol[i] = table_Ass.getColumnModel().getColumn(i);
				Ass_TableCol[i]
						.addPropertyChangeListener(new Ass_ColumnListener());
			}
		}
	}


	/**
	 * to remember the width of the trust certificate table after adjustment form user
	 *
	 */
	class TC_ColumnListener implements PropertyChangeListener {
		@Override
		public void propertyChange(PropertyChangeEvent e) {
			if (e.getPropertyName().equals("preferredWidth")) {

				TableColumn tableColumn = (TableColumn) e.getSource();
				int index = table_TC.getColumnModel().getColumnIndex(
						tableColumn.getHeaderValue());
				PreferredWidth_TC[index] = (int) e.getNewValue();

			}
		}
	}

	/**
	 * to remember the width of the untrust certificate table after adjustment form user
	 *
	 */
	class uTC_ColumnListener implements PropertyChangeListener {
		@Override
		public void propertyChange(PropertyChangeEvent e) {
			if (e.getPropertyName().equals("preferredWidth")) {

				TableColumn tableColumn = (TableColumn) e.getSource();
				int index = table_uTC.getColumnModel().getColumnIndex(
						tableColumn.getHeaderValue());
				PreferredWidth_uTC[index] = (int) e.getNewValue();

			}
		}
	}


	/**
	 * to remember the width of the trust assessment table after adjustment form user
	 *
	 */
	class Ass_ColumnListener implements PropertyChangeListener {
		@Override
		public void propertyChange(PropertyChangeEvent e) {
			if (e.getPropertyName().equals("preferredWidth")) {

				TableColumn tableColumn = (TableColumn) e.getSource();
				int index = table_Ass.getColumnModel().getColumnIndex(
						tableColumn.getHeaderValue());
				PreferredWidth_Ass[index] = (int) e.getNewValue();

			}
		}
	}


	/**
	 * rewrite the mouselistener for adjusting the table width
	 *
	 */
	class Ass_ModelListener implements TableModelListener {
		@Override
		public void tableChanged(TableModelEvent e) {

			TrustAssessment Clicked_Ass = GUILogic.getAss_by_Click(table_Ass);
			TrustAssessment new_Ass = Clicked_Ass;
			String Change = (String) table_Ass.getValueAt(e.getFirstRow(),
					e.getColumn());

			String regex = "^\\s*\\(\\s*(\\s*0\\.[0-9]+|1\\.0)\\s*,\\s*(0\\.[0-9]+|1\\.0)\\s*,\\s*(0\\.[0-9]+|1\\.0\\s*)\\s*\\)\\s*$";

			if (!Change.matches(regex)) {
				GUILogic.msg("Please enter the valid value(between 0.0 and 1.0) for each item. example:(0.5, 0.5, 0.5)");

				if (e.getColumn() == 3)
					Change = "(" + Clicked_Ass.getO_it_ca().getT() + ", "
							+ Clicked_Ass.getO_it_ca().getC() + ", "
							+ Clicked_Ass.getO_it_ca().getF() + ")";
				else if (e.getColumn() == 4)
					Change = "(" + Clicked_Ass.getO_it_ee().getT() + ", "
							+ Clicked_Ass.getO_it_ee().getC() + ", "
							+ Clicked_Ass.getO_it_ee().getF() + ")";

				table_Ass.setValueAt(Change, e.getFirstRow(), e.getColumn());
				return;
			}// if

			Change = Change.substring(Change.indexOf("(") + 1,
					Change.indexOf(")"));

			double T, C, F;
			String[] tcf = Change.split(",");

			T = Double.valueOf(tcf[0]);
			C = Double.valueOf(tcf[1]);
			F = Double.valueOf(tcf[2]);
			CertainTrust new_CertT;

			if (e.getColumn() == 3) {
				new_CertT = new CertainTrust(T, C, F, Clicked_Ass.getO_it_ca()
						.getN());
				new_CertT.setRS(Clicked_Ass.getO_it_ca().getR(), Clicked_Ass
						.getO_it_ca().getS());
				new_Ass = new TrustAssessment(Clicked_Ass.getK(),
						Clicked_Ass.getCa(), Clicked_Ass.getS(),
						Clicked_Ass.getO_kl(), new_CertT,
						Clicked_Ass.getO_it_ee());

			} else if (e.getColumn() == 4) {
				new_CertT = new CertainTrust(T, C, F, Clicked_Ass.getO_it_ee()
						.getN());
				new_CertT.setRS(Clicked_Ass.getO_it_ee().getR(), Clicked_Ass
						.getO_it_ee().getS());
				new_Ass = new TrustAssessment(Clicked_Ass.getK(),
						Clicked_Ass.getCa(), Clicked_Ass.getS(),
						Clicked_Ass.getO_kl(), Clicked_Ass.getO_it_ca(),
						new_CertT);

			}

			try {
				TrustView view = data.Model.openTrustView();
				view.setAssessment(new_Ass);
				view.close();

			} catch (ModelAccessException e1) {
				GUILogic.msg("Error reading or concurrent modifying the database! ");

				e1.printStackTrace();
			}

			table_Ass.setModel(GUILogic.refresh_Ass_Table());
			refresh_ColWidth();

		}
	}


	class componentAdapter extends java.awt.event.ComponentAdapter {
		GUI frame;

		  componentAdapter(GUI frame) {
		    this.frame = frame;
		  }
		  @Override
		public void componentResized(ComponentEvent e) {
			  frame.Frame_Resized(e);
		  }
		}
}

