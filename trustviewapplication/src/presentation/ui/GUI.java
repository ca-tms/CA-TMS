package presentation.ui;

import java.awt.EventQueue;

import javax.swing.JFrame;

import data.TrustCertificate;
import data.TrustView;

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
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JComboBox;

import presentation.logic.PresentationLogic;












import java.awt.event.ItemListener;
import java.awt.event.ItemEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class GUI {

	private JFrame frame;
	
	private JTable table_TC;
	private JTable table_uTC;
	private JTextField textField;
	private JTable table_Ass;
	private int[] PreferredWidth_TC ={120,120,120,120,120,120};
	private int[] PreferredWidth_uTC ={120,120,120,120,120,120};
	TableColumn[] Trust_Cert_TableCol= new TableColumn[6];
	TableColumn[] UnTrust_Cert_TableCol= new TableColumn[6];
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

	@SuppressWarnings({ "unchecked" })
	private void initialize() {
		
		try{
			   UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
			  }catch(Exception e){
			  }
		
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


		
		
		DefaultTableModel Model_TC=PresentationLogic.refresh_TC_Table();
		table_TC =  new JTable(Model_TC);
		table_TC.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		refresh_ColWidth(table_TC,PreferredWidth_TC);
		
		scrollPane_TC.setViewportView(table_TC);

		// ////////////////////////////////////////////////////////////////Popupmenu for TrustCertificate_Table////////////////////////////////////////////////////

		final JPopupMenu PopMenu_TrustCert = new JPopupMenu();
		final JMenuItem Insert_TC = new JMenuItem("Insert");
		final JMenuItem Delete_TC = new JMenuItem("Delete");
		final JMenuItem Set_uTC = new JMenuItem("Set untrust");
		
		
		PopMenu_TrustCert.add(Insert_TC);
		PopMenu_TrustCert.add(Delete_TC);
		PopMenu_TrustCert.add(Set_uTC);
		
		///////////////////////////////////////////////////////////////////////////////////////Listener////////////////////////////////////////////////////
		scrollPane_TC.addMouseListener(new MouseAdapter() {
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

		///////////////////////////////////////////////////////////////////////////Insert menu//////////////////////////////////////////////
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

					
						try {
							X509Certificate cert = PresentationLogic.LoadCert(Cert_Path);
							TrustView view = data.Model.openTrustView();
							view.setTrustedCertificate(new TrustCertificate(cert));
							view.close();
							
							table_TC.setModel(PresentationLogic.refresh_TC_Table());
							refresh_ColWidth(table_TC,PreferredWidth_TC);
						
							
						} catch (CertificateException e) {
							JOptionPane.showConfirmDialog(null,
									"Cannot create a TrustCertificate from not X.509 Certificate ",
									"Error", JOptionPane.DEFAULT_OPTION);
							e.printStackTrace();
						} catch (IOException e) {
							if(Cert_Path.equals(""))
								return;
							else
							JOptionPane.showConfirmDialog(null,
									"Error reading Certificate File ",
									"Error", JOptionPane.DEFAULT_OPTION);
							e.printStackTrace();
						} catch (Exception e) {
							JOptionPane.showConfirmDialog(null,
									"Error reading or concurrent modifying the database! ",
									"Error", JOptionPane.DEFAULT_OPTION);
							e.printStackTrace();
						}
				
					
					
						
				}
			}
		}
		);
		//////////////////////////////////////////////////////////////Delete//////////////////////////////////////////////////////////
		Delete_TC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1|| arg0.getButton() == 3) {
					
					
						JOptionPane.showConfirmDialog(null,
								"to be done, delete cert ",
								"Error", JOptionPane.DEFAULT_OPTION);
					
				}	
			}}
		);
		//////////////////////////////////////////////////////////////Set untrust//////////////////////////////////////////////////////////
		Set_uTC.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent arg0) {
				if (arg0.getButton() == 1|| arg0.getButton() == 3) {
					
					
					TrustCertificate uTCertificate=PresentationLogic.getTCert_by_Click(table_TC);
					TrustView view;
					try {
						view = data.Model.openTrustView();
						view.setUntrustedCertificate(uTCertificate);
						view.close();
						
						table_TC.setModel(PresentationLogic.refresh_TC_Table());
						table_uTC.setModel(PresentationLogic.refresh_uTC_Table());
						refresh_ColWidth(table_TC,PreferredWidth_TC);
						refresh_ColWidth(table_uTC,PreferredWidth_uTC);
						
					} catch (Exception e) {
						JOptionPane.showConfirmDialog(null,
								"Error reading or concurrent modifying the database! ",
								"Error", JOptionPane.DEFAULT_OPTION);
						e.printStackTrace();
					}

					
				}	
			}}
		);
				
		
		
		// ///////////////////////////////////////////////////////////////////unTrustCertificate_panel////////////////////////////////////////////////////////////

		JPanel panel_uTC = new JPanel();
		tabbedPane.addTab("unTrusted Certificates", null, panel_uTC, null);
		panel_uTC.setLayout(null);

		JScrollPane scrollPane_uTC = new JScrollPane();
		scrollPane_uTC.setBounds(10, 10, 739, 554);
		panel_uTC.add(scrollPane_uTC);
		// ///////////////////////////////////////////////////////////////////unTrustCertificate_Table////////////////////////////////////////////////////////////
		


		table_uTC =  new JTable(PresentationLogic.refresh_uTC_Table());
		refresh_ColWidth(table_uTC,PreferredWidth_uTC);
		scrollPane_uTC.setViewportView(table_uTC);
		
		
		// ////////////////////////////////////////////////////////////////Popupmenu for unTrustCertificate_Table////////////////////////////////////////////////////

				final JPopupMenu PopMenu_unTrustCert = new JPopupMenu();
				final JMenuItem Insert_uTC = new JMenuItem("Insert");
				final JMenuItem Delete_uTC = new JMenuItem("Delete");
				final JMenuItem Set_TC = new JMenuItem("Set trust");

				
				PopMenu_unTrustCert.add(Insert_uTC);
				PopMenu_unTrustCert.add(Delete_uTC);
				PopMenu_unTrustCert.add(Set_TC);
	
				
				
				
///////////////////////////////////////////////////////////////////////////////////////Listener////////////////////////////////////////////////////

				


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
				scrollPane_uTC.addMouseListener(new MouseAdapter() {
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

////////////////////////////////////////////////////////////////////////////////////////////Insert for unTrustCertificate//////////////////////////////////////////////////////
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

							
								try {
									X509Certificate cert = PresentationLogic.LoadCert(Cert_Path);
									TrustView view = data.Model.openTrustView();
									view.setUntrustedCertificate(new TrustCertificate(cert));
									view.close();
									
									table_uTC.setModel(PresentationLogic.refresh_uTC_Table());
									refresh_ColWidth ( table_uTC, PreferredWidth_uTC);
								
									
								} catch (CertificateException e) {
									JOptionPane.showConfirmDialog(null,
											"Cannot create a TrustCertificate from not X.509 Certificate ",
											"Error", JOptionPane.DEFAULT_OPTION);
									e.printStackTrace();
								} catch (IOException e) {
									if(Cert_Path.equals(""))
										return;
									else
									JOptionPane.showConfirmDialog(null,
											"Error reading Certificate File ",
											"Error", JOptionPane.DEFAULT_OPTION);
									e.printStackTrace();
								} catch (Exception e) {
									JOptionPane.showConfirmDialog(null,
											"Error reading or concurrent modifying the database! ",
											"Error", JOptionPane.DEFAULT_OPTION);
									e.printStackTrace();
								}
						
							
							
								
						}}}
				);
		///////////////////////////////////////////////////////////////////Delete_uTC/////////////////////////////////////////////////////////////		
				Delete_uTC.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.DEFAULT_OPTION);
							
						}	
					}}
				);
				
				///////////////////////////////////////////////////////////////////Set_TC/////////////////////////////////////////////////////////////		
				Set_TC.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							TrustCertificate TCertificate=PresentationLogic.getuTCert_by_Click(table_uTC);
							TrustView view;
							try {
								view = data.Model.openTrustView();
								view.setTrustedCertificate(TCertificate);
								view.close();
								
								table_TC.setModel(PresentationLogic.refresh_TC_Table());
								table_uTC.setModel(PresentationLogic.refresh_uTC_Table());
								refresh_ColWidth(table_TC,PreferredWidth_TC);
								refresh_ColWidth(table_uTC,PreferredWidth_uTC);
								
							} catch (Exception e) {
								JOptionPane.showConfirmDialog(null,
										"Error reading or concurrent modifying the database! ",
										"Error", JOptionPane.DEFAULT_OPTION);
								e.printStackTrace();
							}

							
						}	
						}	
					}
				);
						
				
			
		// ///////////////////////////////////////////////////////////////////unTrustCertificate_Table////////////////////////////////////////////////////////////
		
		

		JPanel panel_Ass = new JPanel();
		tabbedPane.addTab("Assessments Management", null, panel_Ass, null);
		panel_Ass.setLayout(null);

		JScrollPane scrollPane_Ass = new JScrollPane();
		scrollPane_Ass.setBounds(10, 10, 739, 554);
		panel_Ass.add(scrollPane_Ass);
		// ///////////////////////////////////////////////////////////////////Assessment_Table////////////////////////////////////////////////////////////
		



		table_Ass = new JTable(PresentationLogic.refresh_Ass_Table());
		scrollPane_Ass.setViewportView(table_Ass);
		// ////////////////////////////////////////////////////////////////Popupmenu for ASS////////////////////////////////////////////////////

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
						}}});

				
				Insert_Ass.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.DEFAULT_OPTION);
							
						}	
					}}
				);
				
				Delete_Ass.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.DEFAULT_OPTION);
							
						}	
					}}
				);
			
						
				
				Edit_Ass.addMouseListener(new MouseAdapter() {
					public void mousePressed(MouseEvent arg0) {
						if (arg0.getButton() == 1|| arg0.getButton() == 3) {
							
							
								JOptionPane.showConfirmDialog(null,
										"to be done, delete cert ",
										"Error", JOptionPane.DEFAULT_OPTION);
								
							
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
	
	public void refresh_ColWidth (JTable table,int [] PreferredWidth)
	{
		DefaultTableColumnModel cmodel = (DefaultTableColumnModel)table.getColumnModel();
		for (int i = 0; i < table.getColumnCount(); i++) {
		TableColumn column = cmodel.getColumn(i);
		column.setPreferredWidth(PreferredWidth[i]);
		}
		if(table_TC!=null)
		for(int i=0;i<Trust_Cert_TableCol.length;i++)
		{
			Trust_Cert_TableCol[i]= table_TC.getColumnModel().getColumn(i);
			Trust_Cert_TableCol[i].addPropertyChangeListener(new TC_ColumnListener ());
		}
		if(table_uTC!=null)
			for(int i=0;i<UnTrust_Cert_TableCol.length;i++)
			{
			UnTrust_Cert_TableCol[i]= table_uTC.getColumnModel().getColumn(i);
		UnTrust_Cert_TableCol[i].addPropertyChangeListener(new uTC_ColumnListener ());
	}}
	
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
}
