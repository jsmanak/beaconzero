Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/noble64"
  config.vm.network "forwarded_port", guest: 8080, host: 8080
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096"
    vb.cpus = 2
  end
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update -y
    sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1 lsm=landlock,lockdown,yama,integrity,apparmor,bpf"/' /etc/default/grub
    update-grub
    apt-get install -y build-essential clang llvm libbpf-dev linux-tools-common bpftool
  SHELL
end
