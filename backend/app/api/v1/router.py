from fastapi import APIRouter

api_router = APIRouter()

# Future module routers (e.g. auth, cases, emails, forensics) will be included here:
# api_router.include_router(cases_router, prefix="/cases", tags=["Cases"])
# api_router.include_router(emails_router, prefix="/emails", tags=["Emails"])
# api_router.include_router(forensics_router, prefix="/forensics", tags=["Forensics"])
