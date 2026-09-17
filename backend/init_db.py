import sys
import os
import json

# Add backend directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.db.base import Base
from app.db.postgres import engine
from sqlalchemy.orm import sessionmaker
import app.models.orm as orm

print("Creating database tables...")
Base.metadata.create_all(bind=engine)
print("Database tables created successfully!")

# Seed Framework, Controls and Checks
print("Seeding Framework, Controls, and Compliance Checks...")
SessionLocal = sessionmaker(bind=engine)
db_session = SessionLocal()

try:
    # 1. Seed Framework
    fw = db_session.query(orm.FrameworkORM).filter_by(framework_id="SOC2").first()
    if not fw:
        fw = orm.FrameworkORM(
            framework_id="SOC2",
            name="SOC 2",
            description="SOC 2 Compliance Framework",
            status="ACTIVE"
        )
        db_session.add(fw)
        db_session.commit()
        print("Framework SOC2 seeded.")

    # 2. Seed Controls and Checks from library.json
    base_dir = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(base_dir, "app", "domain", "checks", "library.json")
    
    with open(path, "r") as f:
        checks_data = json.load(f)
        for cdata in checks_data:
            # Upsert control
            num = int(cdata["check_id"].split("-")[1])
            ctrl_id = f"CM-CONTROL-{num:02d}"
            if num > 11:
                ctrl_id = "CM-CONTROL-01"
            
            ctrl = db_session.query(orm.ControlORM).filter_by(control_id=ctrl_id).first()
            if not ctrl:
                ctrl = orm.ControlORM(
                    control_id=ctrl_id,
                    framework_id="SOC2",
                    criterion="CC8.1",
                    name=f"Control {ctrl_id}",
                    objective="Ensure compliance control",
                    description="Control description",
                    lifecycle_stage="Authorization",
                    status="ACTIVE",
                    version="1.0.0"
                )
                db_session.add(ctrl)
                db_session.commit()
                print(f"Control {ctrl_id} seeded.")

            # Upsert check
            check_id = cdata["check_id"]
            chk = db_session.query(orm.ComplianceCheckORM).filter_by(check_id=check_id).first()
            if not chk:
                chk = orm.ComplianceCheckORM(
                    check_id=check_id,
                    control_id=ctrl_id,
                    name=cdata["name"],
                    description=cdata["description"],
                    category=cdata["category"],
                    severity=cdata["severity"],
                    lifecycle_stage="Testing",
                    required_data=cdata["required_fields"],
                    evaluation_logic=cdata["logic"],
                    evidence_requirements=cdata.get("evidence_requirements", []),
                    result_types=["PASS", "FAIL", "INSUFFICIENT_DATA", "NOT_APPLICABLE", "ERROR"],
                    status="ACTIVE",
                    version=cdata.get("version", "1.0.0"),
                    reremediation_guidance="Fix compliance check violation."
                )
                db_session.add(chk)
                print(f"Check {check_id} seeded.")
                
        db_session.commit()
        print("Framework, Controls, and Compliance Checks seeded successfully!")
        
except Exception as e:
    db_session.rollback()
    print(f"Error seeding database: {e}")
finally:
    db_session.close()
