#
# Cookbook Name:: cm
# Recipe:: default
#
# Copyright 2017, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#
#ssh-keygen -t rsa -N "" -f my.key
#
#

user "#{node['user']}" do
  shell '/bin/bash'
  home "/home/#{node['user']}"
  manage_home true
  action :create
end

bash "Generate SSH private/public keys..." do
  code <<-EOH
    su - sysadmin
    ssh-keygen -t rsa -N "" -f my.key
  EOH
  not_if { File.exists?("/home/#{node['user']}/my.key") }
end
bash "Disable root login..." do
  code <<-EOH
    sed -i.bak 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
  EOH
end
bash "Allow restricted users to login..." do
  code <<-EOH
    ( echo ""; echo "AllowUsers ec2-user" ) >> /etc/ssh/sshd_config
  EOH
end

if node['platform_family'] == 'rhel'
  service 'sshd' do
    action :restart
  end
elsif node['platform_family'] == 'debian'
  service 'ssh' do
    action :restart
  end
else
  puts "This recipe is not supported on #{node['platform_family']}"
end

package "mysql-server" do
  action :install
end
service 'mysqld' do
  action :restart
end
bash "Configure root password..." do
  code <<-EOH
    mysqladmin -u root password newpass
  EOH
end
bash "Create new user foo..." do
  code <<-EOH
SQL="GRANT ALL ON *.* TO 'foo'@'localhost' IDENTIFIED BY 'bar';"
mysql -uroot -pnewpass -e "$SQL"
  EOH
end

# Apache configuration
#
if node['platform_family'] == 'rhel'

  %w(httpd php).each do |pkg|
    package "#{pkg}" do
      action :install
    end
  end
  
  cookbook_file "#{node['apache']['doc_root']}/phpinfo.php" do
    source 'phpinfo.txt'
    #owner 'root'
    #group 'root'
    #mode 0744
  end
  
  service 'httpd' do
    action [:restart, :enable]
  end

elsif node['platform_family'] == 'debian'

  %w(apache2 php).each do |pkg|
    package "#{pkg}" do
      action :install
    end
  end

  cookbook_file "#{node['apache']['doc_root']}/phpinfo.php" do
    source 'phpinfo.txt'
    #owner 'root'
    #group 'root'
    #mode 0744
  end

  service 'apache2' do
    action [:restart, :enable]
  end

else
  puts "This recipe is not supported on #{node['platform_family']}"
end

