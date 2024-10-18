from fpdf import FPDF


# Function to generate a PDF with EICAR content
def generate_eicar_pdf(filename):
    eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    # Create a new PDF
    pdf = FPDF()
    pdf.add_page()

    # Add the EICAR test text
    pdf.set_font('Arial', 'B', 12)
    pdf.multi_cell(0, 10, eicar_string)

    # Save the PDF file
    pdf.output(filename)
    print(f"PDF saved as {filename}")

# We generate a PDF file named eicar_test.pdf
generate_eicar_pdf("eicar_test.pdf")