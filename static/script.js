async function checkURL() {
  const url = document.getElementById("urlInput").value;
  const resultDiv = document.getElementById("result");

  resultDiv.innerHTML = "⏳ Scanning...";

  try {
    const response = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    const data = await response.json();

    resultDiv.innerHTML = `
            <h3>Scan Result</h3>
            <p><strong>${data.result}</strong></p>
            <p>Phishing Probability: ${data.phishing_probability}%</p>
            <p>Legitimate Probability: ${data.legitimate_probability}%</p>
        `;
  } catch (error) {
    resultDiv.innerHTML = "❌ Error connecting to server";
  }
}
