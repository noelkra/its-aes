using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using AesFileCrypt.Core;
using Microsoft.Win32;

namespace AesFileCrypt.App;

public partial class MainWindow : Window
{
    private sealed record ModeItem(AesMode Mode, string Name);

    private const string Extension = ".aes";
    private readonly bool _initialized;
    private bool _busy;

    private bool IsEncrypt => EncryptRadio.IsChecked == true;

    public MainWindow()
    {
        InitializeComponent();

        var modes = AesModeInfo.All
            .Select(m => new ModeItem(m, AesModeInfo.DisplayName(m) + (AesModeInfo.IsAuthenticated(m) ? " (authenticated)" : "")))
            .ToList();
        ModeCombo.ItemsSource = modes;
        ModeCombo.SelectedItem = modes.First(m => m.Mode == AesMode.Gcm);
        KeySizeCombo.ItemsSource = new[] { 128, 192, 256 };
        KeySizeCombo.SelectedItem = 256;

        _initialized = true;
        UpdateOperationUi();
    }

    private void Operation_Changed(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        UpdateOperationUi();
        SuggestOutputPath();
    }

    private void UpdateOperationUi()
    {
        EncryptOptions.Visibility = IsEncrypt ? Visibility.Visible : Visibility.Collapsed;
        RunButton.Content = IsEncrypt ? "ENCRYPT" : "DECRYPT";
        StatusText.Text = string.Empty;
        Progress.Value = 0;
        UpdateInfoText();
    }

    private void ModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_initialized) UpdateInfoText();
    }

    private void InputBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_initialized) return;
        SuggestOutputPath();
        UpdateInfoText();
    }

    /// <summary>Encrypt: shows the description of the chosen mode. Decrypt: shows what the file header says.</summary>
    private void UpdateInfoText()
    {
        if (IsEncrypt)
        {
            InfoText.Text = ModeCombo.SelectedItem is ModeItem item ? AesModeInfo.Description(item.Mode) : string.Empty;
            return;
        }

        InfoText.Text = "The mode, key size and all other parameters are read from the encrypted file. Only the key is needed.";
        if (!File.Exists(InputBox.Text)) return;

        try
        {
            var h = AesFileCipher.ReadHeader(InputBox.Text);
            InfoText.Text = $"Detected: AES-{h.KeySizeBits}-{AesModeInfo.DisplayName(h.Mode)}, " +
                            $"PBKDF2-HMAC-SHA256 with {h.Iterations:N0} iterations.";
        }
        catch (Exception ex) when (ex is InvalidFileFormatException or IOException or UnauthorizedAccessException)
        {
            InfoText.Text = ex.Message;
        }
    }

    private void SuggestOutputPath()
    {
        var input = InputBox.Text.Trim();
        if (input.Length == 0)
        {
            OutputBox.Text = string.Empty;
            return;
        }

        if (IsEncrypt)
            OutputBox.Text = input + Extension;
        else
            OutputBox.Text = input.EndsWith(Extension, StringComparison.OrdinalIgnoreCase)
                ? input[..^Extension.Length]
                : input + ".decrypted";
    }

    private void BrowseInput_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = IsEncrypt ? "Select the file to encrypt" : "Select the file to decrypt",
            Filter = IsEncrypt ? "All files|*.*" : "Encrypted files (*.aes)|*.aes|All files|*.*",
        };
        if (dialog.ShowDialog(this) == true) InputBox.Text = dialog.FileName;
    }

    private void BrowseOutput_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Select the output file",
            FileName = Path.GetFileName(OutputBox.Text),
            Filter = "All files|*.*",
        };
        if (dialog.ShowDialog(this) == true) OutputBox.Text = dialog.FileName;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
        {
            InputBox.Text = files[0];
            if (files[0].EndsWith(Extension, StringComparison.OrdinalIgnoreCase)) DecryptRadio.IsChecked = true;
        }
    }

    private async void RunButton_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;

        var input = InputBox.Text.Trim();
        var output = OutputBox.Text.Trim();
        var key = KeyBox.Password;
        bool encrypt = IsEncrypt;

        if (!File.Exists(input)) { ShowStatus("Please select an existing input file.", isError: true); return; }
        if (output.Length == 0) { ShowStatus("Please choose an output file.", isError: true); return; }
        if (key.Length == 0) { ShowStatus("Please enter a key.", isError: true); return; }
        if (encrypt && key != ConfirmKeyBox.Password) { ShowStatus("The two keys do not match.", isError: true); return; }
        if (File.Exists(output) &&
            MessageBox.Show(this, $"'{output}' already exists. Overwrite it?", "Overwrite file",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        var mode = (ModeCombo.SelectedItem as ModeItem)?.Mode ?? AesMode.Gcm;
        int keyBits = KeySizeCombo.SelectedItem as int? ?? 256;

        SetBusy(true);
        ShowStatus(encrypt ? "Encrypting…" : "Decrypting…", isError: false, neutral: true);
        var progress = new Progress<double>(p => Progress.Value = p);

        try
        {
            await Task.Run(() =>
            {
                if (encrypt) AesFileCipher.Encrypt(input, output, key, mode, keyBits, progress);
                else AesFileCipher.Decrypt(input, output, key, progress);
            });
            ShowStatus($"{(encrypt ? "Encrypted" : "Decrypted")} successfully → {output}", isError: false);
        }
        catch (AuthenticationFailedException ex)
        {
            ShowStatus(ex.Message, isError: true);
        }
        catch (Exception ex) when (ex is InvalidFileFormatException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ShowStatus(ex.Message, isError: true);
        }
        catch (Exception ex)
        {
            ShowStatus($"Unexpected error: {ex.Message}", isError: true);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        RunButton.IsEnabled = !busy;
        Progress.Value = 0;
    }

    private void ShowStatus(string message, bool isError, bool neutral = false)
    {
        StatusText.Text = message;
        StatusText.Foreground = neutral
            ? (Brush)FindResource("MaterialDesign.Brush.Foreground")
            : isError ? new SolidColorBrush(Color.FromRgb(0xC6, 0x28, 0x28)) : new SolidColorBrush(Color.FromRgb(0x2E, 0x7D, 0x32));
    }
}
