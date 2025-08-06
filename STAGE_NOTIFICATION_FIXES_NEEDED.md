# Critical Stage and Notification Fixes Needed

## 1. Database Setup Required

You need to create these groups and assign them to stages:

```sql
-- Create missing groups
INSERT INTO groups (name, description, is_active) VALUES
('TAO Group', 'Technical Assessment Office', true),
('Finance Group', 'Finance Department', true),
('TGL:TA Group', 'Technical Group Leader: Technical Assessment', true),
('STA Group', 'Senior Technical Assessor', true),
('Technical Services Group', 'Technical Services Department', true),
('EMTS Group', 'Executive Manager Technical Services', true),
('TECO Group', 'Technical Committee', true),
('Board Group', 'Board Members', true),
('Board Chairperson Group', 'Board Chairperson', true),
('Project Leader Group', 'Project Leaders', true);

-- Assign groups to stages based on your specification
INSERT INTO stage_group_assignments (stage_id, group_id) VALUES
-- Stage 1: New Application
((SELECT id FROM stages WHERE stage_number = 1.0), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 2: Verification of Application Completeness  
((SELECT id FROM stages WHERE stage_number = 2.0), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 3: Admin Fee Request
((SELECT id FROM stages WHERE stage_number = 3.0), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 4: Admin Invoice Generation
((SELECT id FROM stages WHERE stage_number = 4.0), (SELECT id FROM groups WHERE name = 'Finance Group')),

-- Stage 4.1: Confirmation of Invoice
((SELECT id FROM stages WHERE stage_number = 4.1), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 4.2: Admin fee-Proof of Payment (Client uploads)
((SELECT id FROM stages WHERE stage_number = 4.2), (SELECT id FROM groups WHERE name = 'TAO Group')),
((SELECT id FROM stages WHERE stage_number = 4.2), (SELECT id FROM groups WHERE name = 'Finance Group')),

-- Stage 4.3: Payment Confirmation
((SELECT id FROM stages WHERE stage_number = 4.3), (SELECT id FROM groups WHERE name = 'Finance Group')),
((SELECT id FROM stages WHERE stage_number = 4.3), (SELECT id FROM groups WHERE name = 'TAO Group')),
((SELECT id FROM stages WHERE stage_number = 4.3), (SELECT id FROM groups WHERE name = 'TGL:TA Group')),

-- Stage 5: Allocation: Criteria Review
((SELECT id FROM stages WHERE stage_number = 5.0), (SELECT id FROM groups WHERE name = 'TGL:TA Group')),

-- Stage 5.1: Review: Application Criteria review
((SELECT id FROM stages WHERE stage_number = 5.1), (SELECT id FROM groups WHERE name = 'STA Group')),

-- Stage 6: Peer Review-Criteria Review
((SELECT id FROM stages WHERE stage_number = 6.0), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 6.1: Peer review Committee -Criteria Report
((SELECT id FROM stages WHERE stage_number = 6.1), (SELECT id FROM groups WHERE name = 'STA Group')),

-- Stage 7: Approval - Application Criteria Report
((SELECT id FROM stages WHERE stage_number = 7.0), (SELECT id FROM groups WHERE name = 'TGL:TA Group')),

-- Stage 8: Allocation: Preparation: Assessment Work Offer (AWO)
((SELECT id FROM stages WHERE stage_number = 8.0), (SELECT id FROM groups WHERE name = 'TGL:TA Group')),

-- Stage 8.1: Preparation: Assessment Work Offer (AWO)
((SELECT id FROM stages WHERE stage_number = 8.1), (SELECT id FROM groups WHERE name = 'STA Group')),

-- Stage 8.2: Peer Review-Draft Assessment Work Offer (AWO)
((SELECT id FROM stages WHERE stage_number = 8.2), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 8.3: Peer Committee-Draft Assessment Work Offer
((SELECT id FROM stages WHERE stage_number = 8.3), (SELECT id FROM groups WHERE name = 'STA Group')),

-- Stage 8.4: Review: Approval Submission
((SELECT id FROM stages WHERE stage_number = 8.4), (SELECT id FROM groups WHERE name = 'TGL:TA Group')),

-- Stage 9: Approval: Assessment work offer
((SELECT id FROM stages WHERE stage_number = 9.0), (SELECT id FROM groups WHERE name = 'EMTS Group')),

-- Stage 10: Dispatched Assessment work offer
((SELECT id FROM stages WHERE stage_number = 10.0), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 11: Client Response
((SELECT id FROM stages WHERE stage_number = 11.0), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 11.1: Review: Client Response
((SELECT id FROM stages WHERE stage_number = 11.1), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 12: Evaluation Fee Request
((SELECT id FROM stages WHERE stage_number = 12.0), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 13: Evaluation Invoice Generation
((SELECT id FROM stages WHERE stage_number = 13.0), (SELECT id FROM groups WHERE name = 'Finance Group')),

-- Stage 13.1: Confirmation of Invoice
((SELECT id FROM stages WHERE stage_number = 13.1), (SELECT id FROM groups WHERE name = 'TAO Group')),

-- Stage 13.2: Evaluation fee-Proof of Payment
((SELECT id FROM stages WHERE stage_number = 13.2), (SELECT id FROM groups WHERE name = 'TAO Group')),
((SELECT id FROM stages WHERE stage_number = 13.2), (SELECT id FROM groups WHERE name = 'Finance Group')),

-- Stage 13.3: Payment Confirmation
((SELECT id FROM stages WHERE stage_number = 13.3), (SELECT id FROM groups WHERE name = 'Finance Group')),
((SELECT id FROM stages WHERE stage_number = 13.3), (SELECT id FROM groups WHERE name = 'TAO Group')),
((SELECT id FROM stages WHERE stage_number = 13.3), (SELECT id FROM groups WHERE name = 'TGL:TA Group')),
((SELECT id FROM stages WHERE stage_number = 13.3), (SELECT id FROM groups WHERE name = 'STA Group')),

-- Stage 14: Project Allocation
((SELECT id FROM stages WHERE stage_number = 14.0), (SELECT id FROM groups WHERE name = 'TGL:TA Group')),

-- Stage 14.1: Project Assessment
((SELECT id FROM stages WHERE stage_number = 14.1), (SELECT id FROM groups WHERE name = 'STA Group')),
((SELECT id FROM stages WHERE stage_number = 14.1), (SELECT id FROM groups WHERE name = 'Project Leader Group')),

-- Continue for all remaining stages...
-- Stage 15-20.2 assignments based on your specification
;
```

## 2. Missing Stage Actions

Add these missing stage actions:

```python
# Stage 14.1.3: Review Project Submission (missing from current code)
14.13: [('approved', 'Approved'), ('rejected', 'Rejected')],
```

## 3. Notification Logic Updates Needed

The notification system needs to be updated to handle multiple groups per stage as specified in your workflow.

## 4. Client Notification Improvements

Update client notifications to include proper stage-specific messages and upload instructions.

## Summary

✅ **FIXED:** Final stage completion (20.2 approved)
✅ **FIXED:** Client upload stages (4.2, 13.2)  
✅ **FIXED:** Basic workflow transitions
❌ **NEEDS FIX:** Group assignments to stages
❌ **NEEDS FIX:** Multi-group notifications per stage
❌ **NEEDS FIX:** Stage-specific notification content
❌ **NEEDS FIX:** Missing stage 14.1.3 actions

The core workflow logic is now correct, but you need to set up the database with proper group assignments for notifications to work as specified.