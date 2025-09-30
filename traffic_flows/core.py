from radkit_cli import get_any_single_output, get_single_output_genie, logging_warning, logging_info

def cpu_utilization_warning(step,pids,hostname):
    process = "cpuUtilization"
    subprocess = "[highCPU]"
    error = "CPU Utilization - High CPU"

    if len(pids) == 0:
        message = "No processes are currently exhibiting high utilization."
        logging_info(step, process, subprocess, hostname, error + " | " + message)
    else:
        for entry in pids:
            processname = entry['process']
            processpid = entry['pid']
            process5secutil = entry['five_sec_cpu']
            message = "The process identified as '{}' (PID: {}) has reached a utilization of {}%".format(processname, processpid, process5secutil)
            logging_warning(step, process, subprocess, hostname, error + " | " + message)

def cpu_platform_utilization_warning(step,pids,hostname):
    process = "cpuUtilization"
    subprocess = "[highCPU]"
    error = "CPU Platform Utilization - High CPU"

    if len(pids) == 0:
        message = "No processes are currently exhibiting high utilization."
        logging_info(step, process, subprocess, hostname, error + " | " + message)
    else:
        for entry in pids:
            processname = entry['process']
            processpid = entry['ppid']
            process5secutil = entry['five_sec_cpu']
            message = "The process identified as '{}' (PPID: {}) has reached a utilization of {}%".format(processname, processpid, process5secutil)
            logging_warning(step, process, subprocess, hostname, error + " | " + message)

class CoreDevice:
    def __init__(self,device):
        self.device = device

    def cpu_utilization(self,service):
        hostname = self.device
        cpucmd = "show process cpu sorted | ex 0.00"
        cpuop = get_single_output_genie(hostname,cpucmd,service)

        self.five_sec_cpu_total = None
        self.five_sec_cpu_interrupts = None
        self.nonzero_cpu_processes = None
        self.high_cpu_processes = None
        self.sortedprocesses = None

        if cpuop is not None:
          self.five_sec_cpu_total = cpuop['five_sec_cpu_total']
          self.five_sec_cpu_interrupts = cpuop['five_sec_cpu_interrupts']
          high_cpu_processes = []
          self.nonzero_cpu_processes = cpuop['nonzero_cpu_processes']
          sortedprocesses = []
          for process in cpuop['sort']:
            processinfo = cpuop['sort'][process]
            sortedprocesses.append(processinfo)
            process5secutil = cpuop['sort'][process]['five_sec_cpu']
            if process5secutil > 70:
                high_cpu_processes.append(processinfo)
          self.high_cpu_processes = high_cpu_processes
          self.sortedprocesses = sortedprocesses

    def cpu_utilization_platform(self,service):
        hostname = self.device
        cpucmd = "show processes cpu platform sorted | ex 0%"
        cpuplatop = get_single_output_genie(hostname,cpucmd,service)

        self.five_sec_cpu_interrupts = None
        self.plat_high_cpu_processes = None
        self.plat_sortedprocesses = None

        if cpuplatop is not None:
            self.five_sec_cpu_interrupts = cpuplatop['cpu_utilization']['five_sec_cpu_total']
            plat_high_cpu_processes = []
            plat_sortedprocesses = []
            for process in cpuplatop['sort']:
                processinfo = cpuplatop['sort'][process]
                plat_sortedprocesses.append(processinfo)
                process5secutil = cpuplatop['sort'][process]['five_sec_cpu']
                if process5secutil > 70:
                    plat_high_cpu_processes.append(processinfo)
            self.plat_sortedprocesses = plat_sortedprocesses
            self.plat_high_cpu_processes = plat_high_cpu_processes