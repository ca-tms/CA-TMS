import java.sql.*;

public class SQLite {

	/**
	 * 
	 */
	Connection conn;

	public SQLite() {
		
		try {
			Class.forName("org.sqlite.JDBC");
		    conn= DriverManager.getConnection("jdbc:sqlite:WebPKI.db");

			
			
		} catch (ClassNotFoundException | SQLException e) {
			// TODO �Զ����ɵ� catch ��
			e.printStackTrace();
		}
		
	}

	public static void main(String[] args) {
		// TODO �Զ����ɵķ������
		SQLite sql=new SQLite();
		try {
			Statement stat = sql.conn.createStatement();
			//stat.executeUpdate( "create table temp(name varchar(20), salary int);" );
			stat.executeUpdate( "insert into temp values('cai',8001);" );
			stat.executeUpdate( "insert into temp values('Janik',8002);" );
			stat.executeUpdate( "insert into temp values('Pascal',8003);" );
			
			ResultSet rs = stat.executeQuery("select * from temp;"); //��ѯ���� 

			while (rs.next()) { //����ѯ�������ݴ�ӡ����

			System.out.print("name = " + rs.getString("name") + " "); //������һ

			System.out.println("salary = " + rs.getString("salary")); //�����Զ�
			}
			rs.close();
			
		} catch (SQLException e) {
			// TODO �Զ����ɵ� catch ��
			e.printStackTrace();
		}
	}

}
