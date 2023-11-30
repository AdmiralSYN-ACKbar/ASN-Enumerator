import requests  # Used to make HTTP requests
import tkinter as tk  # Used for GUI
from tkinter import filedialog, ttk # Additional GUI components
import ipaddress  # Used for IP address validation
from datetime import datetime  # Used for timestamp

# Function to get ASN details
import requests  # Used to make HTTP requests
import tkinter as tk  # Used for GUI
from tkinter import filedialog, ttk, messagebox  # Additional GUI components
import ipaddress  # Used for IP address validation
from datetime import datetime  # Used for timestamp

# Global variable to track if the last message was a status message
last_message_status = False

# Function to get ASN details
def get_asn_details(asn, output_box):
    global last_message_status  # Use the global variable
    if not asn.isdigit():  # Check if ASN is a number
        output_box.delete('1.0', tk.END)  # Clear output box
        output_box.insert(tk.END, "Invalid ASN.")  # Display error message
        return

    # Send GET request to BGPView API to get IP prefixes for ASN
    response = requests.get(f"https://api.bgpview.io/asn/{asn}/prefixes")
    data = response.json()  # Parse JSON response

    if response.status_code == 200:  # Check if request was successful
        ipv4_prefixes = data['data']['ipv4_prefixes']  # Get IPv4 prefixes
        ipv6_prefixes = data['data']['ipv6_prefixes']  # Get IPv6 prefixes

        output_box.delete('1.0', tk.END)  # Clear output box

        # Display ASN
        output_box.insert(tk.END, f"ASN: {asn}\n")

        # Display IPv4 prefixes
        output_box.insert(tk.END, f"IPv4 Prefixes:\n")
        for prefix in ipv4_prefixes:
            output_box.insert(tk.END, f"{prefix['prefix']}\n")

        # Display IPv6 prefixes
        output_box.insert(tk.END, f"\nIPv6 Prefixes:\n")
        for prefix in ipv6_prefixes:
            output_box.insert(tk.END, f"{prefix['prefix']}\n")
    else:  # If request was not successful
        output_box.delete('1.0', tk.END)  # Clear output box
        output_box.insert(tk.END, "Could not retrieve data.")  # Display error message
    last_message_status = False  # Set last message status to False to denote that it is not a status message
    return asn  # Return ASN

# Function to get details by name
def get_name_details(name, output_box):
    global last_message_status  # Use the global variable

    # Send GET request to BGPView API to get details by name
    response = requests.get(f"https://api.bgpview.io/search?query_term={name}")
    data = response.json()  # Parse JSON response

    if response.status_code == 200:  # Check if request was successful
        asns = data['data']['asns']  # Get ASNs

        output_box.delete('1.0', tk.END)  # Clear output box

        # Display ASNs
        for asn in asns:
            output_box.insert(tk.END, f"ASN: {asn['asn']}, Name: {asn['name']}, Description: {asn['description']}, Country Code: {asn['country_code']}\n")

    else:  # If request was not successful
        output_box.delete('1.0', tk.END)  # Clear output box
        output_box.insert(tk.END, "Could not retrieve data.")  # Display error message

    last_message_status = False  # Set last message status to False to denote that it is not a status message

# Function to write output to file
def write_to_file(output_box, output_file_entry):
    global last_message_status  # Use the global variable
    output_file = output_file_entry.get()  # Get output file path
    if output_file:  # If output file path is not empty
        try:
            text_to_write = output_box.get('1.0', tk.END)  # Get text from output box
            with open(output_file, 'a') as f:  # Open file for appending
                f.write(text_to_write)  # Write output to file
            num_lines = text_to_write.count('\n')  # Count number of lines
            current_time = datetime.now().strftime('%m-%d-%Y %H:%M:%S')  # Get current time
            # If last message was a status message, replace it with the success message
            if last_message_status:
                output_box.delete('1.0', '2.0')
            output_box.insert('1.0', f"{num_lines} lines written to file at {current_time}\n")
            # Set last_message_status to True because the last message is a status message
            last_message_status = True
        except Exception as e:  # If writing to file failed
            current_time = datetime.now().strftime('%m-%d-%Y %H:%M:%S')  # Get current time
            # If last message was a status message, replace it with the error message
            if last_message_status:
                output_box.delete('1.0', '2.0')
            error_message = str(e).replace(',', '')  # Convert the exception to a string and remove commas
            output_box.insert('1.0', f"{error_message}, write failed at {current_time}\n")
            # Set last_message_status to True because the last message is a status message
            last_message_status = True
                
# Function to browse for a file
def browse_file(entry):
    # Open file dialog to select CSV file
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if filename:  # If a file was selected
        entry.delete(0, tk.END)  # Clear entry field
        entry.insert(0, filename)  # Display file path in entry field

# Function to get ASN for a given IP
def get_ip_asn(ip, output_box):
    global last_message_status  # Use the global variable
    try:
        ipaddress.ip_address(ip)  # Validate IP address
    except ValueError:  # If IP address is invalid
        output_box.delete('1.0', tk.END)  # Clear output box
        output_box.insert(tk.END, "Invalid IP address.")  # Display error message
        last_message_status = False  # Set last message status to False to denote that it is not a status message
        return

    # Send GET request to BGPView API to get ASN for IP
    response = requests.get(f"https://api.bgpview.io/ip/{ip}")
    data = response.json()  # Parse JSON response

    if response.status_code == 200 and 'prefixes' in data['data'] and data['data']['prefixes']:  # Check if request was successful and data is available
        asn = data['data']['prefixes'][0]['asn']['asn']  # Get ASN
        name = data['data']['prefixes'][0]['asn']['name'].replace(',', '')  # Get organization name and remove commas
        description = data['data']['prefixes'][0]['asn']['description'].replace(',', '')  # Get description and remove commas
        country_code = data['data']['prefixes'][0]['asn']['country_code']  # Get country code
        output_box.delete('1.0', tk.END)  # Clear output box
        # Display ASN details
        output_box.insert(tk.END, f"ASN for {ip}: {asn}\n")
        output_box.insert(tk.END, f"Organization: {name}\n")
        output_box.insert(tk.END, f"Description: {description}\n")
        output_box.insert(tk.END, f"Country Code: {country_code}\n")    
    else:  # If request was not successful or data is not available
        output_box.delete('1.0', tk.END)  # Clear output box
        output_box.insert(tk.END, "Could not retrieve data.")  # Display error message

    last_message_status = False  # Set last message status to False to denote that it is not a status message

# Main function to create GUI
def main():
    root = tk.Tk()  # Create root window
    root.title("Admiral SYN-ACKbar's ASN Enumerator")  # Set window title
    root.geometry("500x600")  # Set window size

    frame = ttk.Frame(root, padding="10")  # Create main frame with padding
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))  # Place frame in grid

    # Create title labels and place them in grid
    title_label1 = ttk.Label(frame, text="Admiral SYN-ACKbar's", font=("Sylfaen", 14, "italic"))
    title_label1.grid(row=0, column=0, columnspan=3)
    title_label2 = ttk.Label(frame, text="ASN Enumerator", font=("Sylfaen", 18, "bold"))
    title_label2.grid(row=1, column=0, columnspan=3)

    # Create IP to ASN label, entry field, and button, and place them in grid
    ip_label = ttk.Label(frame, text="IP to ASN:", font=("Sylfaen", 10, "bold"))
    ip_label.grid(row=2, column=0, sticky=tk.W)
    ip_entry = ttk.Entry(frame, width=30)
    ip_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
    ip_button = ttk.Button(frame, text="Lookup", command=lambda: get_ip_asn(ip_entry.get(), output_box))
    ip_button.grid(row=2, column=2, sticky=tk.W)

    # Create ASN to IP label, entry field, and button, and place them in grid
    asn_label = ttk.Label(frame, text="ASN to IP:", font=("Sylfaen", 10, "bold"))
    asn_label.grid(row=3, column=0, sticky=tk.W)
    asn_entry = ttk.Entry(frame, width=30)
    asn_entry.grid(row=3, column=1, sticky=(tk.W, tk.E))
    asn_button = ttk.Button(frame, text="Enumerate", command=lambda: get_asn_details(asn_entry.get(), output_box))
    asn_button.grid(row=3, column=2, sticky=tk.W)

    # Create Name Search label, entry field, and button, and place them in grid
    name_search_label = ttk.Label(frame, text="Name Search:", font=("Sylfaen", 10, "bold"))
    name_search_label.grid(row=4, column=0, sticky=tk.W)
    name_search_entry = ttk.Entry(frame, width=30)
    name_search_entry.grid(row=4, column=1, sticky=(tk.W, tk.E))
    name_search_button = ttk.Button(frame, text="Search", command=lambda: get_name_details(name_search_entry.get(), output_box))
    name_search_button.grid(row=4, column=2, sticky=tk.W)

    # Create output label and text box, and place them in grid
    output_label = ttk.Label(frame, text="Output:", font=("Sylfaen", 14, "bold"))
    output_label.grid(row=5, column=0, sticky=tk.W)
    output_box = tk.Text(frame, width=50, height=20)
    output_box.grid(row=6, column=0, columnspan=4, sticky=(tk.W, tk.E))

    # Create output file label, entry field, and buttons, and place them in grid
    output_file_label = ttk.Label(frame, text="Write Output:", font=("Sylfaen", 10, "bold"))
    output_file_label.grid(row=7, column=0, sticky=tk.W)
    output_file_entry = ttk.Entry(frame, width=30)
    output_file_entry.grid(row=7, column=1, sticky=(tk.W, tk.E))
    output_file_button = ttk.Button(frame, text="Browse", command=lambda: browse_file(output_file_entry))
    output_file_button.grid(row=7, column=2, sticky=tk.W)
    output_file_write_button = ttk.Button(frame, text="Write", command=lambda: write_to_file(output_box, output_file_entry))
    output_file_write_button.grid(row=7, column=3, sticky=tk.W)

    # Configure grid padding for all child widgets of frame
    for child in frame.winfo_children(): 
        child.grid_configure(padx=5, pady=5)

    root.mainloop()  # Start Tkinter event loop

# Check if script is being run directly, and if so, call main function
if __name__ == "__main__":
    main()