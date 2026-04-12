const crypto = require('crypto');
// Assume db is available, or we just pass the db logic directly to the connection pool if we can import it
// From index.js we might have a global pool or we should export it. We'll use a placeholder or see how index.js does it.

const handleXenditInvoiceWebhook = (pool) => async (req, res) => {
    try {
        const xenditToken = process.env.XENDIT_WEBHOOK_TOKEN;
        const incomingToken = req.headers['x-callback-token'];

        // If no token in env, we might want to skip or warn, but let's strictly enforce if it's there
        if (xenditToken && incomingToken !== xenditToken) {
            return res.status(403).json({ error: 'Forbidden: Invalid Token' });
        }

        const invoiceData = req.body;

        if (invoiceData.status === 'PAID' || invoiceData.status === 'SETTLED') {
            const externalId = invoiceData.external_id; 
            const paymentMethod = invoiceData.payment_method;
            const paymentChannel = invoiceData.payment_channel;

            const [result] = await pool.execute(
                `UPDATE transactions SET 
                    status = 'success', 
                    payment_method = ?, 
                    payment_channel = ? 
                 WHERE id = ?`,
                [paymentMethod, paymentChannel, externalId]
            );

            console.log(`[INFO] Pembayaran Xendit sukses untuk transaksi: ${externalId}`);
        }

        return res.status(200).json({ status: 'success' });

    } catch (error) {
        console.error('[ERROR] Webhook processing failed:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
};

module.exports = { handleXenditInvoiceWebhook };
