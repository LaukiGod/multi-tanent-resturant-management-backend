const QRCode = require("qrcode");
const sharp = require("sharp");

/** Escapes text placed inside the SVG label. */
const xmlEscape = (value) =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

/**
 * @param {{slug: string, name: string}} restaurant tenant the table belongs to
 * @param {number} tableNo  printed on the label only
 * @param {string} token    opaque table token; the QR link never exposes the table number
 */
exports.generateTableQRCode = async (restaurant, tableNo, token) => {
  try {
    const serviceUrl = String(process.env.FRONTEND_URL || "").replace(/\/+$/, "");
    // The QR must carry the tenant: the customer app is unauthenticated, so the
    // slug in the URL is the only thing that says which restaurant this is. The
    // table is identified by its opaque token, never the real table number.
    const qrText = `${serviceUrl}/r/${restaurant.slug}/user/table-select/${token}`;

    // 1. Generate clean QR
    const qrBuffer = await QRCode.toBuffer(qrText, {
      errorCorrectionLevel: "H",
      width: 500,
      margin: 2,
      color: {
        dark: "#000000",
        light: "#ffffff",
      },
    });

    // 2. Create SVG label (restaurant + table number BELOW QR)
    const labelHeight = 160;

    const svgLabel = `
      <svg width="500" height="${labelHeight}">
        <rect width="100%" height="100%" fill="white"/>
        <text x="50%" y="42%"
          fill="black"
          font-size="60"
          font-weight="bold"
          text-anchor="middle"
          dominant-baseline="middle"
          font-family="Arial, sans-serif">
          Table ${tableNo}
        </text>
        <text x="50%" y="78%"
          fill="#555555"
          font-size="26"
          text-anchor="middle"
          dominant-baseline="middle"
          font-family="Arial, sans-serif">
          ${xmlEscape(restaurant.name)}
        </text>
      </svg>
    `;

    const labelBuffer = Buffer.from(svgLabel);

    // 3. Extend canvas and add label below QR
    const finalImage = await sharp({
      create: {
        width: 500,
        height: 500 + labelHeight,
        channels: 3,
        background: "#ffffff",
      },
    })
      .composite([
        { input: qrBuffer, top: 0, left: 0 },
        { input: labelBuffer, top: 500, left: 0 },
      ])
      .png()
      .toBuffer();

    return finalImage;

  } catch (err) {
    console.error("QR generation failed:", err);
    throw err;
  }
};
