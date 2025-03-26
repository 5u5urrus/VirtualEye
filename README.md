
# VirtualEye

<table border="0" style="border:none;">
  <tr>
    <td style="border:none;">
      <img src="https://github.com/5u5urrus/VirtualEye/assets/165041037/6fd5bcd6-9d34-446b-8759-41bff0fd42e6"  width="100%" height="100%" alt="VirtualEye Logo">
    </td>
    <td style="border:none;">
      <strong>VirtualEye</strong> is a powerful Python tool designed to automate the process of IP address reverse lookups through the HackerTarget API. It checks for hosts to be alive, can operate with or without an API, and can optionally also leverage the Tor network for anonymous requests, handling multiple IP addresses concurrently and efficiently.
    </td>
  </tr>
</table>

## Features

- **Multiple Modes of Operation**: You can query the API directly without API key, or with an API key, and tha last you have is using Tor mode - designed for educational purposes, which can be used to anonymize requests made to the HackerTarget API.
- **Anonymous IP Reverse Lookup**: Can use Tor to anonymize requests made to the HackerTarget API.
- **Concurrency**: Handles multiple IP addresses at once using threading.
- **Domain Liveliness Check**: Verifies if domains associated with IP addresses are active before outputting them.
- **Flexible Input Options**: Supports direct API calls or anonymous requests through Tor.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/5u5urrus/virtualeye.git
   ```
2. Navigate to the project directory:
   ```bash
   cd virtualeye
   ```
   
## Usage

### Basic Command Structure

```bash
python virtualeye.py <IP_ranges_file> [output_file] [mode] [API_key]
```

- `<IP_ranges_file>`: File containing IP addresses or CIDR ranges to process.
- `[output_file]`: Optional. File to save the live domains found (appends to file).
- `[mode]`: Optional. 'tor' for anonymous requests or 'direct' for direct calls (with or without API keys).
- `[API_key]`: Optional. API key for HackerTarget if not using Tor.

### Examples

1. **Using Tor for anonymous reverse IP lookups**:
   ```bash
   python virtualeye.py ips.txt results.txt tor
   ```
2. **Direct API calls with an API key**:
   ```bash
   python virtualeye.py ips.txt results.txt direct your_api_key
   ```
3. **Process IP addresses or CIDR range without saving output**:
   ```bash
   python virtualeye.py ip.txt
   ```
4. **Using direct mode without an API key**:
   ```bash
   python virtualeye.py ips.txt direct
   ```

## Output

If an output file is specified, VirtualEye will append the live domains associated with each IP address to the file. Each domain is written on a new line preceded by its IP address for easy tracking.

Example output in the terminal:<br>
![Screenshot 2024-04-27 041640123](https://github.com/5u5urrus/VirtualEye/assets/165041037/3a15f6d9-99a9-4555-9abe-23db86854e93)

## Contributing

Contributions to VirtualEye are welcome! Please fork the repository and submit a pull request with your suggested changes.

## License

Distributed under the MIT License. See `LICENSE` for more information.
