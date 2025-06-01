import os
from app import create_app, db
from app.models import User
  # change this to your desired password
app = create_app()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # --- Update admin username temporarily ---
        user = User.query.filter_by(email='pierrecelestin.mugisha@bic.bi').first()
        if user:
            user.username = 'BIC STAFF'  # Change to your desired username
            db.session.commit()
        # --- End of temporary block ---

        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port)
    
