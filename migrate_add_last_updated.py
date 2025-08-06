
#!/usr/bin/env python3
"""
Migration script to add missing last_updated column to certificates table
"""

import os
import sys
from datetime import datetime
from sqlalchemy import create_engine, text

# Add the current directory to Python path to import app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def migrate_database():
    """Add the missing last_updated column to certificates table"""
    
    # Database connection string from app config
    database_url = 'postgresql://postgres.xwxeyzwmbypzzlmgfkcq:ash1951@aws-0-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require'
    
    try:
        engine = create_engine(database_url)
        
        with engine.connect() as connection:
            # Check if the column already exists
            result = connection.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'certificates' 
                AND column_name = 'last_updated'
            """))
            
            if result.fetchone() is None:
                print("Adding last_updated column to certificates table...")
                
                # Add the last_updated column
                connection.execute(text("""
                    ALTER TABLE certificates 
                    ADD COLUMN last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                """))
                
                # Update existing records to have a last_updated value
                connection.execute(text("""
                    UPDATE certificates 
                    SET last_updated = created_at 
                    WHERE last_updated IS NULL
                """))
                
                # Make the column NOT NULL after setting values
                connection.execute(text("""
                    ALTER TABLE certificates 
                    ALTER COLUMN last_updated SET NOT NULL
                """))
                
                connection.commit()
                print("✅ Successfully added last_updated column to certificates table")
            else:
                print("✅ last_updated column already exists in certificates table")
                
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("Starting database migration...")
    success = migrate_database()
    if success:
        print("🎉 Migration completed successfully!")
    else:
        print("💥 Migration failed!")
        sys.exit(1)
