"""
Migration script to add workspace tables and columns to existing database.
Run this once to update the database schema.
"""
from app import app, db

def migrate():
    with app.app_context():
        # Add workspace_id column to file table
        try:
            db.session.execute(db.text('''
                ALTER TABLE file ADD COLUMN workspace_id INTEGER REFERENCES workspace(id)
            '''))
            db.session.commit()
            print("Added workspace_id column to file table")
        except Exception as e:
            if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                print("workspace_id column already exists in file table")
            else:
                print(f"Note for file.workspace_id: {e}")
        
        # Create workspace table
        try:
            db.create_all()
            print("Created workspace tables successfully")
        except Exception as e:
            print(f"Note: {e}")
        
        print("Migration completed!")

if __name__ == "__main__":
    migrate()
