require('dotenv').config();
const { Xendit } = require('xendit-node');

const xenditClient = new Xendit({
    secretKey: process.env.XENDIT_SECRET_KEY || 'dummy_key',
});

async function createPesantrenSubAccount(email, businessName) {
    try {
        const response = await xenditClient.Account.createAccount({
            data: {
                email: email,
                type: 'MANAGED', // User wants full control without admin interference
                publicProfile: {
                    businessName: businessName
                }
            }
        });
        return response;
    } catch (error) {
        console.error('Error creating Xendit Managed Account:', error.message);
        throw new Error('Gagal mendaftar sub-account Xendit. Periksa kembali kelengkapan data.');
    }
}

async function createSplitPaymentInvoice(subAccountId, invoiceParams) {
    try {
        const payload = {
            data: {
                externalId: invoiceParams.transactionId,
                amount: invoiceParams.totalAmount,
                payerEmail: invoiceParams.payerEmail,
                description: `Pembayaran Santri - ${invoiceParams.description}`,
                
                fees: [
                    {
                        type: 'PLATFORM_FEE',
                        value: invoiceParams.platformFee
                    }
                ],
                
                successRedirectUrl: process.env.XENDIT_SUCCESS_URL || 'http://localhost:3000/wallet',
                failureRedirectUrl: process.env.XENDIT_FAILURE_URL || 'http://localhost:3000/wallet'
            },
            forUserId: subAccountId 
        };

        const invoice = await xenditClient.Invoice.createInvoice(payload);
        return invoice;
    } catch (error) {
        console.error('Error creating split payment invoice:', error.message);
        throw error;
    }
}

async function withdrawPesantrenBalance(subAccountId, withdrawalParams) {
    try {
        const idempotencyKey = `wd_${subAccountId}_${withdrawalParams.referenceId}`;

        const payload = {
            data: {
                referenceId: withdrawalParams.referenceId,
                channelCode: withdrawalParams.bankCode,
                accountName: withdrawalParams.accountName,
                accountNumber: withdrawalParams.accountNumber,
                description: `Pencairan Saldo Pesantren: ${withdrawalParams.referenceId}`,
                amount: withdrawalParams.amount,
            },
            forUserId: subAccountId,
            headers: {
                'X-IDEMPOTENCY-KEY': idempotencyKey 
            }
        };

        const disbursement = await xenditClient.Payout.createPayout(payload);
        return disbursement;

    } catch (error) {
        console.error('Error processing payout:', error.message);
        throw new Error('Gagal memproses penarikan dana. Silakan coba beberapa saat lagi.');
    }
}

module.exports = {
    createPesantrenSubAccount,
    createSplitPaymentInvoice,
    withdrawPesantrenBalance
};
