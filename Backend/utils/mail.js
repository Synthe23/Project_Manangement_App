import Mailgen from "mailgen";
import nodemailer from "nodemailer";

// 
const sendEmail = async (options) => {
    const mailGenerator = new Mailgen({
        theme: "default",
        product: {
            name: "Project Manager",
            link: "http://projectmanagerlink.com"
        }
    })

    const emailTextual = mailGenerator.generatePlaintext(options.mailgenContent);
    const emailHtml = mailGenerator.generate(options.mailgenContent);

    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_SMTP_HOST,
        port: process.env.MAILTRAP_SMTP_PORT,
        auth: {
            user: process.env.MAILTRAP_SMTP_USER,
            pass: process.env.MAILTRAP_SMTP_PASS
        }
    })

    const mail = {
        from: "mail.taskmanager@example.com",
        to: options.email,
        subject: options.subject,
        text: emailTextual,
        html: emailHtml
    }

    try {
        await transporter.sendMail(mail)
    } catch (error) {
        console.error("Email serive failed! Make sure you provided credentials in the .env file", error);
    }
}

// Email verification 
const emailVerificationMailgenContent = (userName, verificationUrl) => {
  return {
    body: {
      name: userName,
      intro: "Welcome to our App we are excited top have you on board!",
      action: {
        instructions:
          "To verify your email please click on the following button",
        button: {
          color: "#06C666",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro:
        "Need help, or do you have any questions? Just reply to the email and we would love to help you!",
    },
  };
};

// Password reset
const forgotPasswordMailgenContent = (userName, passwordResetUrl) => {
  return {
    body: {
      name: userName,
      intro: "We got a request to reset your password of the account!",
      action: {
        instructions:
          "To reset the password click on the following button or the link...",
        button: {
          color: "#0066FF",
          text: "Reset your password",
          link: passwordResetUrl,
        },
      },
      outro:
        "Need help, or do you have any questions? Just reply to the email and we would love to help you!",
    },
  };
};

export { emailVerificationMailgenContent, forgotPasswordMailgenContent, sendEmail };
