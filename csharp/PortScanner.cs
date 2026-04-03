using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SmartScan
{
    public class PortScannerForm : Form
    {
        // UI Components
        private TextBox txtTarget;
        private TextBox txtPorts;
        private NumericUpDown numTimeout;
        private ComboBox cmbPreset;
        private Button btnStart;
        private Button btnStop;
        private ProgressBar progressBar;
        private Label lblStatus;
        private Label lblProgress;
        private DataGridView dgvResults;
        private Label lblOpenCount;
        private CheckBox chkServiceDetection;
        private GroupBox grpOptions;
        private GroupBox grpResults;
        private StatusStrip statusStrip;
        private ToolStripStatusLabel statusLabel;
        private ToolStripProgressBar toolProgress;

        // Scan variables
        private CancellationTokenSource cancellationTokenSource;
        private bool isScanning = false;
        private int totalPorts = 0;
        private int scannedPorts = 0;
        private List<PortResult> results = new List<PortResult>();

        // Service names for common ports
        private Dictionary<int, string> serviceNames = new Dictionary<int, string>
        {
            {20, "FTP-data"}, {21, "FTP"}, {22, "SSH"}, {23, "Telnet"},
            {25, "SMTP"}, {53, "DNS"}, {80, "HTTP"}, {110, "POP3"},
            {111, "RPC"}, {135, "RPC"}, {139, "NetBIOS"}, {143, "IMAP"},
            {443, "HTTPS"}, {445, "SMB"}, {993, "IMAPS"}, {995, "POP3S"},
            {1723, "PPTP"}, {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"},
            {5900, "VNC"}, {6379, "Redis"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"},
            {27017, "MongoDB"}
        };

        public PortScannerForm()
        {
            InitializeComponent();
            SetupForm();
        }

        private void InitializeComponent()
        {
            this.txtTarget = new TextBox();
            this.txtPorts = new TextBox();
            this.numTimeout = new NumericUpDown();
            this.cmbPreset = new ComboBox();
            this.btnStart = new Button();
            this.btnStop = new Button();
            this.progressBar = new ProgressBar();
            this.lblStatus = new Label();
            this.lblProgress = new Label();
            this.dgvResults = new DataGridView();
            this.lblOpenCount = new Label();
            this.chkServiceDetection = new CheckBox();
            this.grpOptions = new GroupBox();
            this.grpResults = new GroupBox();
            this.statusStrip = new StatusStrip();
            this.statusLabel = new ToolStripStatusLabel();
            this.toolProgress = new ToolStripProgressBar();
            
            ((System.ComponentModel.ISupportInitialize)(this.numTimeout)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.dgvResults)).BeginInit();
            this.grpOptions.SuspendLayout();
            this.grpResults.SuspendLayout();
            this.statusStrip.SuspendLayout();
            this.SuspendLayout();
            
            // txtTarget
            this.txtTarget.Font = new Font("Consolas", 11F);
            this.txtTarget.Location = new Point(20, 50);
            this.txtTarget.Size = new Size(300, 28);
            this.txtTarget.Text = "google.com";
            
            // txtPorts
            this.txtPorts.Font = new Font("Consolas", 11F);
            this.txtPorts.Location = new Point(20, 110);
            this.txtPorts.Size = new Size(300, 28);
            this.txtPorts.Text = "1-1000";
            
            // numTimeout
            this.numTimeout.Font = new Font("Consolas", 11F);
            this.numTimeout.Location = new Point(20, 170);
            this.numTimeout.Minimum = 100;
            this.numTimeout.Maximum = 5000;
            this.numTimeout.Value = 500;
            this.numTimeout.Increment = 100;
            
            // cmbPreset
            this.cmbPreset.Font = new Font("Consolas", 11F);
            this.cmbPreset.Location = new Point(20, 230);
            this.cmbPreset.Size = new Size(300, 29);
            this.cmbPreset.Items.AddRange(new object[] {
                "Custom", "Quick Scan (Top 24)", "Common Web (80,443,8080,8443)",
                "Database (3306,5432,27017,1433)", "Full Range (1-65535)"
            });
            this.cmbPreset.SelectedIndex = 1;
            this.cmbPreset.SelectedIndexChanged += CmbPreset_SelectedIndexChanged;
            
            // chkServiceDetection
            this.chkServiceDetection.Font = new Font("Consolas", 10F);
            this.chkServiceDetection.Location = new Point(20, 270);
            this.chkServiceDetection.Size = new Size(200, 24);
            this.chkServiceDetection.Text = "Enable Service Detection";
            this.chkServiceDetection.Checked = true;
            
            // btnStart
            this.btnStart.BackColor = Color.FromArgb(35, 134, 54);
            this.btnStart.FlatStyle = FlatStyle.Flat;
            this.btnStart.Font = new Font("Consolas", 12F, FontStyle.Bold);
            this.btnStart.ForeColor = Color.White;
            this.btnStart.Location = new Point(20, 310);
            this.btnStart.Size = new Size(140, 40);
            this.btnStart.Text = "▶ START SCAN";
            this.btnStart.UseVisualStyleBackColor = false;
            this.btnStart.Click += BtnStart_Click;
            
            // btnStop
            this.btnStop.BackColor = Color.FromArgb(248, 81, 73);
            this.btnStop.FlatStyle = FlatStyle.Flat;
            this.btnStop.Font = new Font("Consolas", 12F, FontStyle.Bold);
            this.btnStop.ForeColor = Color.White;
            this.btnStop.Location = new Point(180, 310);
            this.btnStop.Size = new Size(140, 40);
            this.btnStop.Text = "■ STOP";
            this.btnStop.UseVisualStyleBackColor = false;
            this.btnStop.Enabled = false;
            this.btnStop.Click += BtnStop_Click;
            
            // progressBar
            this.progressBar.Location = new Point(20, 370);
            this.progressBar.Size = new Size(300, 20);
            
            // lblStatus
            this.lblStatus.Font = new Font("Consolas", 10F);
            this.lblStatus.Location = new Point(20, 400);
            this.lblStatus.Size = new Size(300, 30);
            this.lblStatus.Text = "Ready";
            
            // lblProgress
            this.lblProgress.Font = new Font("Consolas", 9F);
            this.lblProgress.ForeColor = Color.Gray;
            this.lblProgress.Location = new Point(20, 430);
            this.lblProgress.Size = new Size(300, 20);
            this.lblProgress.Text = "0%";
            
            // lblOpenCount
            this.lblOpenCount.Font = new Font("Consolas", 11F, FontStyle.Bold);
            this.lblOpenCount.ForeColor = Color.FromArgb(63, 185, 80);
            this.lblOpenCount.Location = new Point(20, 460);
            this.lblOpenCount.Size = new Size(300, 30);
            this.lblOpenCount.Text = "Open ports: 0";
            
            // grpOptions
            this.grpOptions.Controls.AddRange(new Control[] {
                this.txtTarget, this.txtPorts, this.numTimeout, this.cmbPreset,
                this.chkServiceDetection, this.btnStart, this.btnStop,
                this.progressBar, this.lblStatus, this.lblProgress, this.lblOpenCount
            });
            this.grpOptions.Font = new Font("Consolas", 10F, FontStyle.Bold);
            this.grpOptions.Location = new Point(12, 12);
            this.grpOptions.Size = new Size(350, 510);
            this.grpOptions.Text = " SCAN OPTIONS ";
            
            // dgvResults
            this.dgvResults.AllowUserToAddRows = false;
            this.dgvResults.AllowUserToDeleteRows = false;
            this.dgvResults.BackgroundColor = Color.FromArgb(13, 17, 23);
            this.dgvResults.BorderStyle = BorderStyle.None;
            this.dgvResults.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dgvResults.Font = new Font("Consolas", 10F);
            this.dgvResults.GridColor = Color.FromArgb(48, 54, 61);
            this.dgvResults.Location = new Point(10, 30);
            this.dgvResults.ReadOnly = true;
            this.dgvResults.RowHeadersVisible = false;
            this.dgvResults.Size = new Size(620, 440);
            this.dgvResults.TabIndex = 0;
            
            // Setup DataGridView columns
            this.dgvResults.Columns.Add("port", "PORT");
            this.dgvResults.Columns.Add("service", "SERVICE");
            this.dgvResults.Columns.Add("status", "STATUS");
            this.dgvResults.Columns.Add("time", "RESPONSE TIME");
            
            this.dgvResults.Columns[0].Width = 100;
            this.dgvResults.Columns[1].Width = 180;
            this.dgvResults.Columns[2].Width = 100;
            this.dgvResults.Columns[3].Width = 150;
            
            this.dgvResults.Columns[0].DefaultCellStyle.ForeColor = Color.FromArgb(88, 166, 255);
            this.dgvResults.Columns[1].DefaultCellStyle.ForeColor = Color.FromArgb(210, 168, 73);
            this.dgvResults.Columns[2].DefaultCellStyle.ForeColor = Color.FromArgb(63, 185, 80);
            this.dgvResults.Columns[3].DefaultCellStyle.ForeColor = Color.FromArgb(139, 148, 158);
            
            // grpResults
            this.grpResults.Controls.Add(this.dgvResults);
            this.grpResults.Font = new Font("Consolas", 10F, FontStyle.Bold);
            this.grpResults.Location = new Point(375, 12);
            this.grpResults.Size = new Size(645, 510);
            this.grpResults.Text = " SCAN RESULTS ";
            
            // statusStrip
            this.statusStrip.Items.AddRange(new ToolStripItem[] { this.statusLabel, this.toolProgress });
            this.statusStrip.Location = new Point(0, 535);
            this.statusStrip.Size = new Size(1032, 22);
            
            // statusLabel
            this.statusLabel.Text = " SmartScan v1.0 - by Prasad";
            
            // toolProgress
            this.toolProgress.Visible = false;
            
            // Form
            this.AutoScaleMode = AutoScaleMode.Font;
            this.BackColor = Color.FromArgb(13, 17, 23);
            this.ClientSize = new Size(1032, 557);
            this.Controls.Add(this.grpOptions);
            this.Controls.Add(this.grpResults);
            this.Controls.Add(this.statusStrip);
            this.Font = new Font("Consolas", 9F);
            this.ForeColor = Color.FromArgb(201, 209, 217);
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.Name = "PortScannerForm";
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Text = "SmartScan - Advanced Port Scanner";
            
            ((System.ComponentModel.ISupportInitialize)(this.numTimeout)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.dgvResults)).EndInit();
            this.grpOptions.ResumeLayout(false);
            this.grpOptions.PerformLayout();
            this.grpResults.ResumeLayout(false);
            this.statusStrip.ResumeLayout(false);
            this.statusStrip.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        private void SetupForm()
        {
            // Set colors for text boxes
            txtTarget.BackColor = Color.FromArgb(13, 17, 23);
            txtTarget.ForeColor = Color.FromArgb(201, 209, 217);
            txtTarget.BorderStyle = BorderStyle.FixedSingle;
            
            txtPorts.BackColor = Color.FromArgb(13, 17, 23);
            txtPorts.ForeColor = Color.FromArgb(201, 209, 217);
            txtPorts.BorderStyle = BorderStyle.FixedSingle;
            
            numTimeout.BackColor = Color.FromArgb(13, 17, 23);
            numTimeout.ForeColor = Color.FromArgb(201, 209, 217);
            
            cmbPreset.BackColor = Color.FromArgb(13, 17, 23);
            cmbPreset.ForeColor = Color.FromArgb(201, 209, 217);
            cmbPreset.FlatStyle = FlatStyle.Flat;
            
            chkServiceDetection.ForeColor = Color.FromArgb(201, 209, 217);
            
            progressBar.Style = ProgressBarStyle.Continuous;
        }

        private void CmbPreset_SelectedIndexChanged(object sender, EventArgs e)
        {
            switch (cmbPreset.SelectedIndex)
            {
                case 0: // Custom
                    txtPorts.Enabled = true;
                    txtPorts.Text = "1-1000";
                    break;
                case 1: // Quick Scan
                    txtPorts.Enabled = false;
                    txtPorts.Text = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,27017";
                    break;
                case 2: // Common Web
                    txtPorts.Enabled = false;
                    txtPorts.Text = "80,443,8080,8443";
                    break;
                case 3: // Database
                    txtPorts.Enabled = false;
                    txtPorts.Text = "3306,5432,27017,1433";
                    break;
                case 4: // Full Range
                    txtPorts.Enabled = false;
                    txtPorts.Text = "1-65535";
                    break;
            }
        }

        private List<int> ParsePorts(string portSpec)
        {
            var ports = new List<int>();
            
            if (portSpec.Contains('-'))
            {
                var parts = portSpec.Split('-');
                if (parts.Length == 2 && int.TryParse(parts[0], out int start) && int.TryParse(parts[1], out int end))
                {
                    for (int i = start; i <= end && i <= 65535; i++)
                    {
                        ports.Add(i);
                    }
                }
            }
            else if (portSpec.Contains(','))
            {
                foreach (var part in portSpec.Split(','))
                {
                    if (int.TryParse(part.Trim(), out int port) && port > 0 && port <= 65535)
                    {
                        ports.Add(port);
                    }
                }
            }
            else
            {
                if (int.TryParse(portSpec, out int port) && port > 0 && port <= 65535)
                {
                    ports.Add(port);
                }
            }
            
            return ports;
        }

        private string GetServiceName(int port)
        {
            return serviceNames.ContainsKey(port) ? serviceNames[port] : "Unknown";
        }

        private async Task<PortResult> ScanPortAsync(string host, int port, int timeoutMs, bool detectService)
        {
            var result = new PortResult { Port = port, IsOpen = false };
            
            try
            {
                using (var tcpClient = new TcpClient())
                {
                    var connectTask = tcpClient.ConnectAsync(host, port);
                    var completedTask = await Task.WhenAny(connectTask, Task.Delay(timeoutMs));
                    
                    if (completedTask == connectTask && tcpClient.Connected)
                    {
                        result.IsOpen = true;
                        result.ResponseTime = "Connected";
                        
                        if (detectService)
                        {
                            result.Service = GetServiceName(port);
                        }
                        else
                        {
                            result.Service = "Open";
                        }
                        
                        tcpClient.Close();
                    }
                    else
                    {
                        result.Service = "Closed/Filtered";
                    }
                }
            }
            catch
            {
                result.Service = "Closed/Filtered";
            }
            
            return result;
        }

        private async void BtnStart_Click(object sender, EventArgs e)
        {
            if (isScanning) return;
            
            // Validate target
            string target = txtTarget.Text.Trim();
            if (string.IsNullOrEmpty(target))
            {
                MessageBox.Show("Please enter a target IP or hostname.", "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            
            // Resolve hostname
            string ipAddress = target;
            try
            {
                var ips = await Dns.GetHostAddressesAsync(target);
                if (ips.Length > 0)
                {
                    ipAddress = ips[0].ToString();
                    statusLabel.Text = $" Resolved: {target} → {ipAddress}";
                }
            }
            catch
            {
                statusLabel.Text = $" Could not resolve: {target}";
            }
            
            // Parse ports
            var ports = ParsePorts(txtPorts.Text);
            if (ports.Count == 0)
            {
                MessageBox.Show("Invalid port specification.", "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            
            totalPorts = ports.Count;
            scannedPorts = 0;
            results.Clear();
            dgvResults.Rows.Clear();
            
            int timeout = (int)numTimeout.Value;
            bool detectService = chkServiceDetection.Checked;
            
            isScanning = true;
            btnStart.Enabled = false;
            btnStop.Enabled = true;
            txtTarget.Enabled = false;
            txtPorts.Enabled = false;
            cmbPreset.Enabled = false;
            progressBar.Maximum = totalPorts;
            progressBar.Value = 0;
            toolProgress.Visible = true;
            toolProgress.Maximum = totalPorts;
            toolProgress.Value = 0;
            
            cancellationTokenSource = new CancellationTokenSource();
            var token = cancellationTokenSource.Token;
            
            lblStatus.Text = $"Scanning {target}...";
            lblProgress.Text = $"0 / {totalPorts} ports (0%)";
            lblOpenCount.Text = "Open ports: 0";
            
            int openCount = 0;
            
            await Task.Run(async () =>
            {
                var options = new ParallelOptions
                {
                    MaxDegreeOfParallelism = 200,
                    CancellationToken = token
                };
                
                var lockObj = new object();
                
                await Parallel.ForEachAsync(ports, options, async (port, ct) =>
                {
                    ct.ThrowIfCancellationRequested();
                    
                    var result = await ScanPortAsync(ipAddress, port, timeout, detectService);
                    
                    lock (lockObj)
                    {
                        scannedPorts++;
                        if (result.IsOpen)
                        {
                            results.Add(result);
                            openCount++;
                            
                            this.Invoke(new Action(() =>
                            {
                                dgvResults.Rows.Insert(0, result.Port, result.Service, "OPEN", result.ResponseTime);
                                lblOpenCount.Text = $"Open ports: {openCount}";
                            }));
                        }
                        
                        int percent = (int)((double)scannedPorts / totalPorts * 100);
                        
                        this.Invoke(new Action(() =>
                        {
                            progressBar.Value = scannedPorts;
                            toolProgress.Value = scannedPorts;
                            lblProgress.Text = $"{scannedPorts} / {totalPorts} ports ({percent}%)";
                            lblStatus.Text = $"Scanning... {percent}% complete - Found {openCount} open ports";
                        }));
                    }
                });
            }, token);
            
            if (!token.IsCancellationRequested)
            {
                lblStatus.Text = $"✓ Scan complete! Found {openCount} open port(s) on {target}";
                statusLabel.Text = $" Scan complete - {openCount} open ports found";
            }
            else
            {
                lblStatus.Text = $"✗ Scan cancelled by user";
                statusLabel.Text = $" Scan cancelled";
            }
            
            isScanning = false;
            btnStart.Enabled = true;
            btnStop.Enabled = false;
            txtTarget.Enabled = true;
            txtPorts.Enabled = cmbPreset.SelectedIndex == 0;
            cmbPreset.Enabled = true;
            toolProgress.Visible = false;
        }

        private void BtnStop_Click(object sender, EventArgs e)
        {
            if (isScanning && cancellationTokenSource != null)
            {
                cancellationTokenSource.Cancel();
                lblStatus.Text = "Stopping scan...";
                statusLabel.Text = " Stopping scan...";
            }
        }
    }

    public class PortResult
    {
        public int Port { get; set; }
        public string Service { get; set; }
        public bool IsOpen { get; set; }
        public string ResponseTime { get; set; }
    }

    public static class Program
    {
        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new PortScannerForm());
        }
    }
}