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
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
		
	}

	public static void main(String[] args) {
		// TODO 自动生成的方法存根
		SQLite sql=new SQLite();
		try {
			Statement stat = sql.conn.createStatement();
			//stat.executeUpdate( "create table temp(name varchar(20), salary int);" );
			stat.executeUpdate( "insert into temp values('cai',8001);" );
			stat.executeUpdate( "insert into temp values('Janik',8002);" );
			stat.executeUpdate( "insert into temp values('Pascal',8003);" );
			
			ResultSet rs = stat.executeQuery("select * from temp;"); //查询数据 

			while (rs.next()) { //将查询到的数据打印出来

			System.out.print("name = " + rs.getString("name") + " "); //列属性一

			System.out.println("salary = " + rs.getString("salary")); //列属性二
			}
			rs.close();
			
		} catch (SQLException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
	}

}
