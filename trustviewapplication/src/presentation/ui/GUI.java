package presentation.ui;

import java.awt.EventQueue;

import javax.swing.JFrame;

import data.TrustCertificate;
import data.TrustView;

import javax.swing.JOptionPane;
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
	
	private JTable table;
	private JTable table_1;
	private JTextField textField;
	private JTable table_2;

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
		
		JPanel panel = new JPanel();
		tabbedPane.addTab("Trusted Certificates", null, panel, null);
		panel.setLayout(null);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(10, 10, 739, 554);
		panel.add(scrollPane);
		
		table = new JTable();
		
		DefaultTableModel Model_TrustCert_Table= new DefaultTableModel(
			new Object[][] {
			},
			new String[] {
				"Serial", "Issuer", "Subject", "PublicKey"
			}
		) {
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] {
				String.class, String.class, String.class, String.class
			};
			@SuppressWarnings({ "rawtypes" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}
			boolean[] columnEditables = new boolean[] {
					false, false, false, false
			};
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		};
		
		Collection<TrustCertificate> Certs_temp=null;
		
		try {
			TrustView view= data.Model.openTrustView();
			Certs_temp =view.getTrustedCertificates();
			view.close();
			
		} catch (Exception e1) {
			JOptionPane.showConfirmDialog(null, "Error reading or concurrent modifying the database! ", "Error", JOptionPane.ERROR_MESSAGE);
			e1.printStackTrace();
		}
		
		Iterator<TrustCertificate> it =Certs_temp.iterator();
		TrustCertificate Certificate;
		
		while(it.hasNext())  {   
		Certificate   =  (TrustCertificate) it.next(); 
		
		Model_TrustCert_Table.addRow(new Object[]{Certificate.getSerial(),Certificate.getIssuer(),Certificate.getSubject(),Certificate.getPublicKey()});
		
		}  
		
		table.setModel(Model_TrustCert_Table);
		scrollPane.setViewportView(table);
		

		
		JPanel panel_2 = new JPanel();
		tabbedPane.addTab("unTrusted Certificates", null, panel_2, null);
		panel_2.setLayout(null);
		
		JScrollPane scrollPane_1 = new JScrollPane();
		scrollPane_1.setBounds(10, 10, 739, 554);
		panel_2.add(scrollPane_1);
		
		table_1 = new JTable();
		
				DefaultTableModel Model_unTrustCert_Table=new DefaultTableModel(
				new Object[][] {
				},
				new String[] {
					"Serial", "Issuer", "Subject", "PublicKey"
				}
			) {
				@SuppressWarnings("rawtypes")
				Class[] columnTypes = new Class[] {
					String.class, String.class, String.class, String.class
				};
				@SuppressWarnings({ "rawtypes" })
				public Class getColumnClass(int columnIndex) {
					return columnTypes[columnIndex];
				}
				boolean[] columnEditables = new boolean[] {
						false, false, false, false
				};
				public boolean isCellEditable(int row, int column) {
					return columnEditables[column];
				}
			};
			
			
			try {
				TrustView view= data.Model.openTrustView();
				Certs_temp =view.getUntrustedCertificates();
				view.close();
				
			} catch (Exception e1) {
				JOptionPane.showConfirmDialog(null, "Error reading or concurrent modifying the database! ", "Error", JOptionPane.ERROR_MESSAGE);
				e1.printStackTrace();
			}
			
			 it =Certs_temp.iterator();
						
			while(it.hasNext())  {   
			Certificate   =  (TrustCertificate) it.next(); 
			
			Model_TrustCert_Table.addRow(new Object[]{Certificate.getSerial(),Certificate.getIssuer(),Certificate.getSubject(),Certificate.getPublicKey()});
			
			}  
			
			
			table_1.setModel(Model_unTrustCert_Table);
			
			scrollPane_1.setViewportView(table_1);
		scrollPane_1.setViewportView(table_1);
		
		JPanel panel_1 = new JPanel();
		tabbedPane.addTab("Assessments Management", null, panel_1, null);
		panel_1.setLayout(null);
		
		JScrollPane scrollPane_2 = new JScrollPane();
		scrollPane_2.setBounds(10, 10, 739, 554);
		panel_1.add(scrollPane_2);
		
		table_2 = new JTable();
		table_2.setModel(new DefaultTableModel(
			new Object[][] {
			},
			new String[] {
				"PublicKey", "CA", "TrustCertificate", "O_kl", "O_it_ca", "O_it_ee"
			}
		) {
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] {
				String.class, String.class, String.class, String.class, String.class, Object.class
			};
			@SuppressWarnings("rawtypes")
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}
			boolean[] columnEditables = new boolean[] {
				false, false, false, false, false, false
			};
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		});
		table_2.getColumnModel().getColumn(2).setPreferredWidth(111);
		scrollPane_2.setViewportView(table_2);
	
		
		JPanel panel_3 = new JPanel();
		tabbedPane.addTab("Configuration", null, panel_3, null);
		panel_3.setLayout(null);
	
		@SuppressWarnings("rawtypes")
		final JComboBox comboBox = new JComboBox();
		comboBox.setBounds(428, 25, 81, 21);
		panel_3.add(comboBox);
		comboBox.addItem("High");
		comboBox.addItem("Medium");
		comboBox.addItem("Low");
		comboBox.addItem("Custom");
		comboBox.setSelectedIndex(1);
		
		JLabel label_1 = new JLabel("0.95");
		label_1.setBounds(428, 84, 54, 15);
		panel_3.add(label_1);
		
		

		

		
		final JSlider slider = new JSlider();
		slider.setBounds(227, 46, 200, 26);
		panel_3.add(slider);
		slider.setValue(80);
		slider.setMaximum(95);
		slider.setMinimum(60);
		
		JLabel lblSecurityLevel = new JLabel("Security Level :");
		lblSecurityLevel.setBounds(290, 28, 96, 15);
		panel_3.add(lblSecurityLevel);
		
		JLabel label = new JLabel("0.6");
		label.setBounds(227, 84, 54, 15);
		panel_3.add(label);
		
		textField = new JTextField(""+(float)slider.getValue()/100);
		textField.setEditable(false);
		textField.setBounds(313, 81, 45, 21);
		panel_3.add(textField);
		textField.setColumns(10);
		

	
		
		

		slider.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent event) {
				if((JSlider)event.getSource()==slider){
						float val=(float)slider.getValue()/100;
							String str=""+val;
							textField.setText(str);
							comboBox.setSelectedIndex(3);
				}
			}
		});
		comboBox.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) 
					{int level=slider.getValue();
					
					if(comboBox.getSelectedIndex()==0)
						level=95;
					else if(comboBox.getSelectedIndex()==1)
					level=80;
					else if(comboBox.getSelectedIndex()==2)
						level=60;
					
					float val=(float)level/100;
					String str=""+val;
					textField.setText(str);
					slider.setValue(level);
					}
			}
		});
		
		
		JPanel panel_4 = new JPanel();
		tabbedPane.addTab("About", null, panel_4, null);
		
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
